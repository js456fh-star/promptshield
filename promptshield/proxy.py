"""OpenAI-compatible reverse proxy with an injection/data-leak firewall.

Point your app's OpenAI base URL at this server. Each request is scanned
(user + tool messages by default), a canary token is planted in the system
prompt, and the upstream response is scanned for canary echoes, system-prompt
leaks, secrets and PII before it reaches the client.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from collections import Counter
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from .config import Settings
from .detectors.dlp import canary_instruction, new_canary
from .engine import Firewall

log = logging.getLogger("promptshield")


def _content_text(content: Any) -> str:
    """Flatten OpenAI message content (string or list of parts) into text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(p.get("text", "") for p in content if isinstance(p, dict))
    return str(content)


class ScanRequest(BaseModel):
    text: str
    direction: str = "input"
    system_prompt: str | None = None


def create_app(settings: Settings | None = None, firewall: Firewall | None = None,
               transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    settings = settings or Settings()
    firewall = firewall or Firewall.from_settings(settings)
    stats: Counter = Counter()
    client = httpx.AsyncClient(base_url=settings.upstream_url.rstrip("/"),
                               timeout=settings.timeout_s, transport=transport)

    @asynccontextmanager
    async def lifespan(_app):
        yield
        await client.aclose()

    app = FastAPI(title="PromptShield", version="0.1.0", lifespan=lifespan)

    def _blocked(verdict, request_id: str, message: str) -> JSONResponse:
        return JSONResponse(status_code=400, headers={"x-promptshield-request-id": request_id}, content={
            "error": {"type": "promptshield_blocked", "code": f"{verdict.direction}_blocked",
                      "message": message, "request_id": request_id, "verdict": verdict.to_dict()}})

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "mode": settings.mode,
                "classifier": firewall.classifier is not None, "threshold": firewall.threshold}

    @app.get("/stats")
    async def get_stats():
        return dict(stats)

    @app.post("/v1/scan")
    async def scan(req: ScanRequest):
        v = (firewall.scan_output(req.text, system_prompt=req.system_prompt)
             if req.direction == "output" else firewall.scan_input(req.text))
        return v.to_dict()

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        rid = uuid.uuid4().hex[:12]
        body = await request.json()
        messages: list[dict] = body.get("messages", [])
        stats["requests"] += 1

        # 1) Inbound scan
        worst = None
        for i, msg in enumerate(messages):
            if msg.get("role") not in settings.scan_roles:
                continue
            v = firewall.scan_input(_content_text(msg.get("content")))
            if worst is None or v.score > worst[1].score:
                worst = (i, v)
        if worst and worst[1].blocked:
            stats["input_flagged"] += 1
            log.warning("rid=%s input flagged msg=%d score=%.2f reasons=%s",
                        rid, worst[0], worst[1].score, worst[1].reasons)
            if settings.mode == "block":
                stats["input_blocked"] += 1
                return _blocked(worst[1], rid, "Request blocked: possible prompt injection detected.")

        # 2) Plant canary in the system prompt
        system_prompt = "\n".join(_content_text(m.get("content")) for m in messages if m.get("role") == "system")
        canary = None
        if settings.canary:
            canary = new_canary()
            messages = [{"role": "system", "content": canary_instruction(canary)}] + messages

        # 3) Forward upstream. Streaming is buffered so the full response can be scanned.
        want_stream = bool(body.get("stream"))
        upstream_body = {**body, "messages": messages, "stream": False}
        upstream_body.pop("stream_options", None)
        headers = {"content-type": "application/json"}
        auth = (f"Bearer {settings.upstream_api_key}" if settings.upstream_api_key
                else request.headers.get("authorization"))
        if auth:
            headers["authorization"] = auth
        t0 = time.perf_counter()
        try:
            resp = await client.post("/v1/chat/completions", json=upstream_body, headers=headers)
        except httpx.HTTPError as e:
            return JSONResponse(status_code=502, content={"error": {"type": "upstream_error", "message": str(e)}})
        upstream_ms = (time.perf_counter() - t0) * 1000
        if resp.status_code >= 400:
            return JSONResponse(status_code=resp.status_code, content=resp.json() if resp.content else {})
        data = resp.json()

        # 4) Outbound scan
        for choice in data.get("choices", []):
            msg = choice.get("message") or {}
            text = _content_text(msg.get("content"))
            if not text:
                continue
            v = firewall.scan_output(text, canary=canary, system_prompt=system_prompt or None)
            if not v.findings:
                continue
            stats["output_flagged"] += 1
            log.warning("rid=%s output flagged score=%.2f reasons=%s", rid, v.score, v.reasons)
            if settings.mode != "block":
                continue
            leak = any(f.rule in {"canary_leak", "system_prompt_leak"} for f in v.findings)
            if leak or (v.blocked and not settings.redact_output):
                stats["output_blocked"] += 1
                return _blocked(v, rid, "Response blocked: possible data leak detected.")
            msg["content"] = firewall.output.redact(text, canary)
            stats["output_redacted"] += 1

        out_headers = {"x-promptshield-request-id": rid,
                       "x-promptshield-input-score": f"{worst[1].score:.3f}" if worst else "0",
                       "x-promptshield-upstream-ms": f"{upstream_ms:.0f}"}
        if want_stream:
            return StreamingResponse(_as_sse(data), media_type="text/event-stream", headers=out_headers)
        return JSONResponse(content=data, headers=out_headers)

    return app


async def _as_sse(data: dict):
    """Re-emit a buffered completion as a minimal OpenAI-style SSE stream."""
    base = {k: data.get(k) for k in ("id", "created", "model")} | {"object": "chat.completion.chunk"}
    for c in data.get("choices", []):
        m = c.get("message", {})
        yield "data: " + json.dumps(base | {"choices": [{"index": c.get("index", 0),
              "delta": {"role": m.get("role", "assistant"), "content": m.get("content", "")},
              "finish_reason": None}]}) + "\n\n"
        yield "data: " + json.dumps(base | {"choices": [{"index": c.get("index", 0), "delta": {},
              "finish_reason": c.get("finish_reason", "stop")}]}) + "\n\n"
    yield "data: [DONE]\n\n"
