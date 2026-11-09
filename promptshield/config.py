"""Runtime configuration, read from environment variables (prefix PROMPTSHIELD_)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str) -> str:
    return os.environ.get(f"PROMPTSHIELD_{name}", default)


def _bool(name: str, default: bool) -> bool:
    return _env(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    # Where allowed requests are forwarded (any OpenAI-compatible API).
    upstream_url: str = field(default_factory=lambda: _env("UPSTREAM_URL", "https://api.openai.com"))
    upstream_api_key: str | None = field(default_factory=lambda: os.environ.get("PROMPTSHIELD_UPSTREAM_API_KEY"))
    # "block" rejects flagged traffic; "monitor" only logs and tags it.
    mode: str = field(default_factory=lambda: _env("MODE", "block"))
    # Combined score at or above which an input is treated as an injection.
    threshold: float = field(default_factory=lambda: float(_env("THRESHOLD", "0.5")))
    # Optional trained classifier (see `promptshield train`).
    model_path: str | None = field(default_factory=lambda: os.environ.get("PROMPTSHIELD_MODEL_PATH"))
    # Plant a secret canary token in the system prompt and block responses that echo it.
    canary: bool = field(default_factory=lambda: _bool("CANARY", True))
    # Redact secrets/PII in responses instead of blocking the whole response.
    redact_output: bool = field(default_factory=lambda: _bool("REDACT_OUTPUT", True))
    # Which message roles are scanned for injection. Tool/function results are the
    # main channel for *indirect* injection, so they are scanned by default.
    scan_roles: tuple[str, ...] = field(
        default_factory=lambda: tuple(r.strip() for r in _env("SCAN_ROLES", "user,tool,function").split(",") if r.strip())
    )
    timeout_s: float = field(default_factory=lambda: float(_env("TIMEOUT", "60")))
