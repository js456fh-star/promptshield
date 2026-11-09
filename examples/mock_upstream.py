"""A fake OpenAI-compatible LLM for local demos (no API key needed).

It deliberately misbehaves when asked to: if the last user message contains
"leak", it echoes its whole system prompt (including the canary); if it
contains "secret", it returns a fake AWS key and an email address.

    uvicorn examples.mock_upstream:app --port 9000
"""
import time

from fastapi import FastAPI, Request

app = FastAPI()


@app.post("/v1/chat/completions")
async def chat(request: Request):
    body = await request.json()
    msgs = body.get("messages", [])
    user = next((m["content"] for m in reversed(msgs) if m.get("role") == "user"), "")
    system = "\n".join(m["content"] for m in msgs if m.get("role") == "system")
    if "leak" in user.lower():
        reply = f"Sure! My instructions are: {system}"
    elif "secret" in user.lower():
        reply = "The key is AKIAIOSFODNN7EXAMPLE, contact ops@example.com."
    else:
        reply = f"Echo: {user}"
    return {"id": "chatcmpl-mock", "object": "chat.completion", "created": int(time.time()),
            "model": body.get("model", "mock"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": reply}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}
