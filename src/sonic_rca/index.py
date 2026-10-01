"""Evidence index: every fact the engine uses gets a stable evidence id."""
from __future__ import annotations

import datetime as _dt
import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .archive import SYSLOG_GLOB, TechsupportSource
from .schema import Evidence

_MAX_EXCERPT = 400

# Log/recording lines older than this (relative to the capture time) are not
# searched. Real images ship months of pre-install log history; correlating
# against it produces confident but irrelevant evidence.
LOG_WINDOW = _dt.timedelta(hours=24)

# container -> the container whose stop takes it down (swss.sh stops its peer
# syncd and dependents bgp/radv/teamd; snmp Requires=swss). Observed on real
# validation image s05: `systemctl stop swss` exits all of these together.
SERVICE_PARENT = {"swss": "database", "syncd": "swss", "bgp": "swss",
                  "teamd": "swss", "radv": "swss", "snmp": "swss"}
_DOWN_STATUS = re.compile(r"^(Exited|Restarting|Dead|Created)\b")

_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
     "Nov", "Dec"), 1)}
# 2026-09-28T08:25:51 | 2026-09-28.08:37:11 (sairedis/swss .rec)
_TS_ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T.](\d{2}):(\d{2}):(\d{2})")
# 2026 Sep 28 08:25:51.317156 (rsyslog on 202605+ images)
_TS_YMD = re.compile(r"^(\d{4}) ([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})")
# Sep 28 08:25:51.3+00:00 [2025] (classic; year optional)
_TS_MDY = re.compile(
    r"^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})\S*(?: (\d{4})\b)?")


def parse_log_ts(line: str, default_year: int) -> Optional[_dt.datetime]:
    try:
        m = _TS_ISO.match(line)
        if m:
            return _dt.datetime(*map(int, m.groups()))
        m = _TS_YMD.match(line)
        if m:
            y, mon, d, hh, mm, ss = m.groups()
            return _dt.datetime(int(y), _MONTHS[mon], int(d), int(hh),
                                int(mm), int(ss))
        m = _TS_MDY.match(line)
        if m:
            mon, d, hh, mm, ss, y = m.groups()
            return _dt.datetime(int(y or default_year), _MONTHS[mon], int(d),
                                int(hh), int(mm), int(ss))
    except (KeyError, ValueError):
        return None
    return None


@dataclass
class LogHit:
    file: str
    lineno: int
    line: str
    evidence_id: str


class EvidenceIndex:
    def __init__(self, source: TechsupportSource,
                 log_window: Optional[_dt.timedelta] = LOG_WINDOW):
        self.src = source
        self.evidence: dict[str, Evidence] = {}
        self._n = 0
        self.log_window = log_window
        self._captured = self._capture_time()
        self._lines: dict[Path, list[tuple[int, str]]] = {}

    def _capture_time(self) -> Optional[_dt.datetime]:
        cap = self.src.meta.get("captured")
        try:
            return _dt.datetime.strptime(cap, "%Y%m%d_%H%M%S") if cap else None
        except ValueError:
            return None

    def _window_lines(self, f: Path) -> list[tuple[int, str]]:
        """Lines of one log file inside the capture window (cached).

        Lines without a parseable timestamp inherit the verdict of the
        previous line (multi-line messages, rec headers).
        """
        if f in self._lines:
            return self._lines[f]
        lo = hi = None
        if self.log_window is not None and self._captured is not None:
            lo = self._captured - self.log_window
            hi = self._captured + _dt.timedelta(hours=1)
        year = self._captured.year if self._captured else 1970
        keep, out = True, []
        for lineno, line in self.src.open_text(f):
            if lo is not None:
                ts = parse_log_ts(line, year)
                if ts is not None:
                    keep = lo <= ts <= hi
            if keep:
                out.append((lineno, line))
        self._lines[f] = out
        return out

    # ---- evidence registry --------------------------------------------------

    def register(self, category: str, source_file: str, locator: str,
                 excerpt: Optional[str] = None) -> str:
        self._n += 1
        ev_id = f"ev:{category}:{self._n:05d}"
        if excerpt and len(excerpt) > _MAX_EXCERPT:
            excerpt = excerpt[:_MAX_EXCERPT] + "…"
        self.evidence[ev_id] = Evidence(id=ev_id, source=source_file,
                                        locator=locator, excerpt=excerpt)
        return ev_id

    def resolve(self, ev_id: str) -> Optional[Evidence]:
        return self.evidence.get(ev_id)

    # ---- DB access ----------------------------------------------------------

    def db_get(self, db: str, pattern: str = "*") -> dict[str, dict]:
        table = self.src.db(db)
        if pattern in ("*", None):
            return dict(table)
        return {k: v for k, v in table.items() if fnmatch.fnmatchcase(k, pattern)}

    def db_key(self, db: str, key: str) -> Optional[dict]:
        return self.src.db(db).get(key)

    def cite_db(self, db: str, key: str) -> str:
        val = self.db_key(db, key)
        if val is not None and "_source" in val:
            return self.register("capture", val["_source"],
                                 f"line {val.get('_lineno', '?')}",
                                 excerpt=val.get("_line") or str(val))
        cat = db.split("_")[0].lower()
        return self.register(cat, self.src.db_file(db), key,
                             excerpt=str(val) if val is not None else None)

    # ---- log / recording search --------------------------------------------

    def search_logs(self, regex: str, name_pattern: str = SYSLOG_GLOB,
                    limit: int = 200, newest: bool = False) -> list[LogHit]:
        """Regex search over log files; each hit is registered as evidence.

        newest=True keeps the `limit` most recent hits by line timestamp
        (across all matched files), oldest first; only those are registered.
        """
        rx = re.compile(regex)
        if newest:
            return self._search_logs_newest(rx, name_pattern, limit)
        hits: list[LogHit] = []
        for f in self.src.log_files(name_pattern):
            for lineno, line in self._window_lines(f):
                if rx.search(line):
                    ev = self.register("log", self.src.rel(f),
                                       f"line {lineno}", excerpt=line)
                    hits.append(LogHit(self.src.rel(f), lineno, line, ev))
                    if len(hits) >= limit:
                        return hits
        return hits

    def _search_logs_newest(self, rx: re.Pattern, name_pattern: str,
                            limit: int) -> list[LogHit]:
        year = self._captured.year if self._captured else 1970
        cands: list[tuple[_dt.datetime, Path, int, str]] = []
        for f in self.src.log_files(name_pattern):
            ts = _dt.datetime.min
            for lineno, line in self._window_lines(f):
                ts = parse_log_ts(line, year) or ts
                if rx.search(line):
                    cands.append((ts, f, lineno, line))
        cands.sort(key=lambda c: c[0])
        hits: list[LogHit] = []
        for _, f, lineno, line in cands[-limit:] if limit > 0 else []:
            ev = self.register("log", self.src.rel(f), f"line {lineno}",
                               excerpt=line)
            hits.append(LogHit(self.src.rel(f), lineno, line, ev))
        return hits

    def search_rec(self, kind: str, needle: str, limit: int = 100) -> list[LogHit]:
        """Substring search across sairedis/swss recordings (gz rotations)."""
        hits: list[LogHit] = []
        for f in self.src.rec_files(kind):
            for lineno, line in self._window_lines(f):
                if needle in line:
                    ev = self.register("rec", self.src.rel(f),
                                       f"line {lineno}", excerpt=line)
                    hits.append(LogHit(self.src.rel(f), lineno, line, ev))
                    if len(hits) >= limit:
                        return hits
        return hits

    def last_rec_op(self, kind: str, needle: str) -> Optional[LogHit]:
        """Most recent recording line mentioning `needle` (bulk lines too).

        rec_files() is newest-first and lines are chronological within a
        file, so the answer is the last hit in the first file that has one.
        Only that line is registered as evidence.
        """
        for f in self.src.rec_files(kind):
            last = None
            for lineno, line in self._window_lines(f):
                if needle in line:
                    last = (lineno, line)
            if last is not None:
                ev = self.register("rec", self.src.rel(f), f"line {last[0]}",
                                   excerpt=last[1])
                return LogHit(self.src.rel(f), last[0], last[1], ev)
        return None

    # ---- health -------------------------------------------------------------

    def health(self) -> dict:
        services = []
        cap = self.src.capture("services.summary")
        if cap:
            for i, line in enumerate(cap.splitlines(), 1):
                low = line.lower()
                if any(w in low for w in ("exited", "restarting", "failed",
                                          "dead", "not running")):
                    ev = self.register("svc", "dump/services.summary",
                                       f"line {i}", excerpt=line)
                    name = line.split()[0] if line.split() else "unknown"
                    services.append({"name": name, "state": "unhealthy",
                                     "evidence": [ev]})
        seen = {s["name"] for s in services}
        for i, name, status, line in self._docker_ps_down():
            if name not in seen:
                ev = self.register("svc", "dump/docker.ps", f"line {i}",
                                   excerpt=line)
                services.append({"name": name, "state": status,
                                 "evidence": [ev]})
                seen.add(name)
        root = [s["name"] for s in services
                if SERVICE_PARENT.get(s["name"]) not in seen]
        cores = []
        for c in self.src.core_dumps():
            ev = self.register("core", c, "present")
            cores.append({"file": c, "evidence": [ev]})
        capture = []
        empty = self.src.current_log_empty("syslog")
        if empty:
            ev = self.register("cap", empty, "empty file")
            capture.append({"issue": "current syslog empty in archive; log "
                                     "correlation limited to rotations",
                            "evidence": [ev]})
        out = {"services": services, "core_dumps": cores, "capture": capture}
        if services:
            out["root_services"] = root
        return out

    def _docker_ps_down(self) -> list[tuple[int, str, str, str]]:
        """(lineno, container, status, line) for non-running containers in
        dump/docker.ps (`docker ps -a` table; columns split on 2+ spaces)."""
        cap = self.src.capture("docker.ps")
        out = []
        for i, line in enumerate((cap or "").splitlines(), 1):
            cols = re.split(r"\s{2,}", line.strip())
            if i == 1 or len(cols) < 5:
                continue
            status = next((c for c in cols[3:] if _DOWN_STATUS.match(c)), None)
            if status:
                out.append((i, cols[-1], status, line))
        return out
