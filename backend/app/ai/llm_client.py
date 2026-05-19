from __future__ import annotations

import time

from google import genai
from google.genai import types

from app.config import Settings

_RETRYABLE_CODES = {503, 504}


def call_llm(system_prompt: str, user_prompt: str) -> str:
    settings = Settings()
    client = genai.Client(
        api_key=settings.gemini_api_key,
        http_options=types.HttpOptions(timeout=60_000),  # 60s per attempt
    )
    last_exc: Exception | None = None
    for attempt in range(3):
        if attempt:
            time.sleep(5 * attempt)  # 5s, 10s back-off
        try:
            response = client.models.generate_content(
                model=settings.gemini_model,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    temperature=0.1,
                ),
            )
            return response.text
        except Exception as exc:
            last_exc = exc
            msg = str(exc)
            if "429" in msg or "quota" in msg.lower() or "api_key" in msg.lower() or "invalid" in msg.lower():
                raise
            if "503" not in msg and "504" not in msg and "service unavailable" not in msg.lower():
                raise
            # 503/504 — retry with back-off
    raise last_exc  # type: ignore[misc]
