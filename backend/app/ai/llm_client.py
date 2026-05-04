from __future__ import annotations

from google import genai
from google.genai import types

from app.config import Settings


def call_llm(system_prompt: str, user_prompt: str) -> str:
    settings = Settings()
    client = genai.Client(api_key=settings.gemini_api_key)
    response = client.models.generate_content(
        model=settings.gemini_model,
        contents=user_prompt,
        config=types.GenerateContentConfig(
            system_instruction=system_prompt,
            temperature=0.1,
        ),
    )
    return response.text
