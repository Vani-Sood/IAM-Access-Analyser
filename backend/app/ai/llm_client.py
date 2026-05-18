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
            code = getattr(getattr(exc, "status_code", None), "real", None) or getattr(exc, "status_code", 0)
            # retry on 503/504; re-raise immediately on 429 (quota) or 4xx
            if isinstance(code, int) and code not in _RETRYABLE_CODES:
                raise
            # extract HTTP code from error message if not on attribute
            msg = str(exc)
            if "429" in msg or "quota" in msg.lower():
                raise
            # 503/504 or unknown server error — retry
    raise last_exc  # type: ignore[misc]
