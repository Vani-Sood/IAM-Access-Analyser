import os
from unittest.mock import MagicMock, patch
import app.ai.llm_client as llm_mod


def _mock_response(text: str = "response text") -> MagicMock:
    r = MagicMock()
    r.text = text
    return r


def test_call_llm_returns_response_text():
    with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key", "GEMINI_MODEL": "gemini-2.5-flash-lite"}):
        with patch.object(llm_mod, "genai") as mock_genai:
            mock_genai.Client.return_value.models.generate_content.return_value = _mock_response("hello")
            result = llm_mod.call_llm("sys", "user")
    assert result == "hello"


def test_call_llm_uses_model_from_env():
    with patch.dict(os.environ, {"GEMINI_API_KEY": "key", "GEMINI_MODEL": "gemini-2.5-pro"}):
        with patch.object(llm_mod, "genai") as mock_genai:
            mock_genai.Client.return_value.models.generate_content.return_value = _mock_response()
            llm_mod.call_llm("sys", "user")
            call_kwargs = str(mock_genai.Client.return_value.models.generate_content.call_args)
            assert "gemini-2.5-pro" in call_kwargs


def test_call_llm_passes_system_instruction():
    with patch.dict(os.environ, {"GEMINI_API_KEY": "key", "GEMINI_MODEL": "gemini-2.5-flash-lite"}):
        with patch.object(llm_mod, "genai") as mock_genai:
            mock_genai.Client.return_value.models.generate_content.return_value = _mock_response()
            llm_mod.call_llm("my system prompt", "my user prompt")
            call_str = str(mock_genai.Client.return_value.models.generate_content.call_args)
            assert "my system prompt" in call_str


def test_call_llm_passes_user_content():
    with patch.dict(os.environ, {"GEMINI_API_KEY": "key", "GEMINI_MODEL": "gemini-2.5-flash-lite"}):
        with patch.object(llm_mod, "genai") as mock_genai:
            mock_genai.Client.return_value.models.generate_content.return_value = _mock_response()
            llm_mod.call_llm("sys", "my user prompt content")
            call_str = str(mock_genai.Client.return_value.models.generate_content.call_args)
            assert "my user prompt content" in call_str


def test_call_llm_uses_api_key():
    with patch.dict(os.environ, {"GEMINI_API_KEY": "secret-key-xyz", "GEMINI_MODEL": "gemini-2.5-flash-lite"}):
        with patch.object(llm_mod, "genai") as mock_genai:
            mock_genai.Client.return_value.models.generate_content.return_value = _mock_response()
            llm_mod.call_llm("sys", "user")
            assert mock_genai.Client.call_args.kwargs["api_key"] == "secret-key-xyz"
