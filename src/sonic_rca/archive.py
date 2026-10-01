"""Archive adapter: normalize a techsupport tarball or extracted dir.

Grounded in sonic-utilities 202605 scripts/generate_dump:
- redis snapshots at dump/<DB>.json in sonic-db-dump -y format
- /var/log sweep under log/ (gzipped rotations), recordings at log/swss/*.rec*
- show-command captures as flat files under dump/
"""
from __future__ import annotations

import fnmatch
import gzip
import io
import json
import re
import tarfile
import tempfile
from pathlib import Path
from typing import Iterator, Optional

from .captures import CAPTURE_DBS
from .schema import TECHSUPPORT_DBS

_DUMP_DIR_RE = re.compile(r"sonic_dump_(?P<host>.+)_(?P<date>\d{8})_(?P<time>\d{6})")

# Top-level archive dirs the engine reads. Real archives also carry etc/,
# proc/, sys/ ... (hundreds of MB, device nodes, dangling links) that the
# engine never touches, so they are not extracted.
_EXTRACT_DIRS = ("dump", "log", "core")

# Classic syslog + its rotations. A bare "syslog*" also matches
# syslog-info.log* / syslog-debug.log* present on newer images.
SYSLOG_GLOB = "syslog|syslog.*"

_ROTATION_RE = re.compile(r"^(?P<base>.+?)(?:\.(?P<n>\d+))?(?:\.gz)?$")


class ArchiveError(RuntimeError):
    pass


def _rotation_key(f: Path) -> tuple:
    m = _ROTATION_RE.match(f.name)
    base, n = (m.group("base"), int(m.group("n") or 0)) if m else (f.name, 0)
    return (str(f.parent), base, n)


def _wanted_members(tf: tarfile.TarFile) -> Iterator[tarfile.TarInfo]:
    """Regular files/dirs under <root>/{dump,log,core}/ with safe paths.

    Real 202605-era captures contain char-device nodes and symlinks under
    etc/ (masked systemd units -> /dev/null) that make a plain extractall
    fail; only regular files and directories are ever needed.
    """
    for m in tf:
        if not (m.isfile() or m.isdir()):
            continue
        parts = Path(m.name).parts
        if m.name.startswith("/") or ".." in parts:
            continue
        top = parts[1] if len(parts) > 1 and parts[0] not in _EXTRACT_DIRS else parts[0]
        if top in _EXTRACT_DIRS:
            yield m


class TechsupportSource:
    """Read-only view over an unpacked (or auto-unpacked) techsupport archive."""

    def __init__(self, path: str | Path):
        p = Path(path)
        if not p.exists():
            raise ArchiveError(f"no such path: {p}")
        if p.is_file():
            self._tmp = tempfile.TemporaryDirectory(prefix="sonic_rca_")
            with tarfile.open(p) as tf:
                members = list(_wanted_members(tf))
                if hasattr(tarfile, "data_filter"):
                    tf.extractall(self._tmp.name, members=members, filter="data")
                else:  # python < 3.9.17 has no extraction filters
                    tf.extractall(self._tmp.name, members=members)
            p = Path(self._tmp.name)
        else:
            self._tmp = None
        self.root = self._find_root(p)
        self.meta = self._read_meta()
        self._db_cache: dict[str, dict[str, dict]] = {}

    @staticmethod
    def _find_root(p: Path) -> Path:
        if (p / "dump").is_dir():
            return p
        candidates = [d for d in p.iterdir() if d.is_dir() and (d / "dump").is_dir()]
        if len(candidates) == 1:
            return candidates[0]
        raise ArchiveError(f"cannot locate techsupport root under {p} "
                           f"(expected a dump/ directory)")

    def _read_meta(self) -> dict:
        meta = {"root": str(self.root)}
        m = _DUMP_DIR_RE.search(self.root.name)
        if m:
            meta.update(hostname=m.group("host"),
                        captured=f'{m.group("date")}_{m.group("time")}')
        ver = self.root / "dump" / "version"
        if ver.is_file():
            txt = ver.read_text(errors="replace")
            meta["version_capture"] = txt[:2000]
            vm = re.search(r"SONiC Software Version:\s*(\S+)", txt)
            if vm:
                meta["sonic_version"] = vm.group(1)
        return meta

    # ---- redis DB snapshots -------------------------------------------------

    def available_dbs(self) -> list[str]:
        out = []
        for db in TECHSUPPORT_DBS:
            if list((self.root / "dump").glob(f"{db}*.json")):
                out.append(db)
        return out

    def db(self, name: str) -> dict[str, dict]:
        """Return {redis_key: {field: value}} for one DB snapshot.

        Accepts sonic-db-dump -y format ({key: {"type":..., "value": {...}}})
        and a flat {key: {field: value}} fallback. Multi-namespace files
        (DB_0.json ...) are merged with a "ns" marker field left intact.
        """
        if name in self._db_cache:
            return self._db_cache[name]
        if name in CAPTURE_DBS:
            return self._capture_db(name)
        files = sorted((self.root / "dump").glob(f"{name}*.json"))
        if not files:
            raise ArchiveError(f"{name} snapshot not present in archive")
        merged: dict[str, dict] = {}
        for f in files:
            raw = json.loads(f.read_text(errors="replace") or "{}")
            for key, entry in raw.items():
                if isinstance(entry, dict) and "value" in entry:
                    val = entry.get("value") or {}
                elif isinstance(entry, dict):
                    val = entry
                else:
                    val = {"_raw": entry}
                merged[key] = val
        self._db_cache[name] = merged
        return merged

    def _capture_db(self, name: str) -> dict[str, dict]:
        """Pseudo-DB parsed from vtysh text captures (see captures.py)."""
        files, parse, prefix = CAPTURE_DBS[name]
        merged: dict[str, dict] = {}
        found = False
        for fname in files:
            text = self.capture(fname)
            if text is None:
                continue
            found = True
            for key, row in parse(text).items():
                merged[f"{prefix}{key}"] = {**row, "_source": f"dump/{fname}"}
        if not found:
            raise ArchiveError(f"{name} captures {files} not present in archive")
        self._db_cache[name] = merged
        return merged

    def db_file(self, name: str) -> str:
        if name in CAPTURE_DBS:
            return f"dump/{CAPTURE_DBS[name][0][0]}"
        files = sorted((self.root / "dump").glob(f"{name}*.json"))
        return str(files[0].relative_to(self.root)) if files else f"dump/{name}.json"

    # ---- logs & recordings --------------------------------------------------

    def log_files(self, pattern: str = "*") -> list[Path]:
        """Files under log/ whose name matches any '|'-separated glob.

        Ordered newest-first per rotation set: `x` / `x.gz` before `x.1.gz`
        before `x.2.gz` ... (real archives gzip even the current file and
        keep 100+ numbered rotations).
        """
        logdir = self.root / "log"
        if not logdir.is_dir():
            return []
        globs = pattern.split("|")
        files = [f for f in logdir.rglob("*")
                 if f.is_file() and any(fnmatch.fnmatch(f.name, g) for g in globs)]
        return sorted(files, key=_rotation_key)

    def rec_files(self, kind: str) -> list[Path]:
        """kind: 'sairedis' or 'swss' -> <kind>.rec* anywhere under log/.

        202605 layout is log/swss/; generate_dump on newer images flattens
        every /var/log file into log/ by basename.
        """
        return self.log_files(f"{kind}.rec|{kind}.rec.*")

    def current_log_empty(self, base: str) -> Optional[str]:
        """Archive-relative path of `base`/`base.gz` if present but empty."""
        for name in (base, f"{base}.gz"):
            f = self.root / "log" / name
            if f.is_file():
                for _ in self.open_text(f):
                    return None
                return self.rel(f)
        return None

    def open_text(self, path: Path) -> Iterator[tuple[int, str]]:
        """Yield (lineno, line) with transparent gzip handling."""
        if path.suffix == ".gz":
            fh = io.TextIOWrapper(gzip.open(path, "rb"), errors="replace")
        else:
            fh = open(path, "r", errors="replace")
        with fh:
            for i, line in enumerate(fh, 1):
                yield i, line.rstrip("\n")

    def rel(self, path: Path) -> str:
        return str(path.relative_to(self.root))

    # ---- misc captures ------------------------------------------------------

    def capture(self, filename: str) -> Optional[str]:
        f = self.root / "dump" / filename
        return f.read_text(errors="replace") if f.is_file() else None

    def core_dumps(self) -> list[str]:
        cdir = self.root / "core"
        if not cdir.is_dir():
            return []
        return [self.rel(f) for f in sorted(cdir.iterdir()) if f.is_file()]
