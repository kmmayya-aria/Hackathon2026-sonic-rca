"""LLM clients for the benchmark — the model is a replaceable component.

`AnthropicClient` uses the Messages API over plain urllib (ANTHROPIC_API_KEY
env var). `ClaudeCodeClient` drives the `claude` CLI in print mode (`-p`),
so a Claude subscription that includes Claude Code works with no API key
(select it with a `cc:` model prefix, e.g. `--model cc:sonnet`). Any other
provider fits by implementing `complete(system, user)`.
`NullClient` lets the harness run end-to-end with the deterministic layer
only (verdict = top finding's suspected stage) — useful for plumbing tests,
never reported as an LLM result.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.request
from typing import Protocol


class LLMClient(Protocol):
    name: str
    def complete(self, system: str, user: str) -> str: ...


class AnthropicClient:
    def __init__(self, model: str, max_tokens: int = 2000):
        self.name = model
        self.model = model
        self.max_tokens = max_tokens
        self.key = os.environ.get("ANTHROPIC_API_KEY")
        if not self.key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")

    def complete(self, system: str, user: str) -> str:
        body = json.dumps({
            "model": self.model, "max_tokens": self.max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages", data=body,
            headers={"content-type": "application/json",
                     "x-api-key": self.key,
                     "anthropic-version": "2023-06-01"})
        with urllib.request.urlopen(req, timeout=120) as r:
            data = json.loads(r.read())
        return "".join(b.get("text", "") for b in data.get("content", []))


class ClaudeCodeClient:
    """Backend = the `claude` CLI in print mode (an official scripted mode),
    so a Claude subscription that includes Claude Code needs no API key.

    Sign in once on the machine (`claude` interactively), then use
    `--model cc:<id>` where <id> is any model Claude Code accepts
    ("sonnet", "haiku", "opus", or a full model id). The system and user
    prompts are combined into one stdin prompt; `--output-format text`
    keeps stdout to the bare completion so the scorer's JSON parse holds.
    """

    def __init__(self, model: str, timeout: int = 300, binary: str = "claude"):
        self.model = model
        self.name = f"claude-code/{model}"
        self.timeout = timeout
        self.binary = binary
        if shutil.which(binary) is None:
            raise RuntimeError(
                f"'{binary}' CLI not found on PATH — install Claude Code and "
                "sign in, or use an API-key client instead")

    def complete(self, system: str, user: str) -> str:
        prompt = f"{system}\n\n---\n\n{user}"
        proc = subprocess.run(
            [self.binary, "-p", "--model", self.model,
             "--output-format", "text"],
            input=prompt, capture_output=True, text=True,
            timeout=self.timeout,
            env={**os.environ, "CLAUDE_CODE_MAX_OUTPUT_TOKENS": "2000"},
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"claude -p failed (rc={proc.returncode}): "
                f"{proc.stderr.strip()[:500]}")
        return proc.stdout.strip()


class NullClient:
    """Deterministic-only plumbing arm; not an LLM result."""
    name = "null(deterministic-only)"

    def complete(self, system: str, user: str) -> str:
        try:
            rep = json.loads(user[user.index('{'):user.rindex('}') + 1])
            f = (rep.get("findings") or [{}])[0]
            return json.dumps({"root_cause_stage": f.get("suspected_stage", "unknown"),
                               "summary": "deterministic top finding",
                               "evidence": f.get("evidence", [])})
        except Exception:
            return json.dumps({"root_cause_stage": "unknown",
                               "summary": "no parse", "evidence": []})


def make_client(model: str | None) -> LLMClient:
    if model is None:
        return NullClient()
    if model.startswith("cc:"):
        return ClaudeCodeClient(model[3:])
    return AnthropicClient(model)
