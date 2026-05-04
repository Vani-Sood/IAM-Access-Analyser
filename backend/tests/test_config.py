import os
import pytest
from unittest.mock import patch


def make_settings(**overrides):
    """Instantiate Settings with controlled env, bypassing .env file."""
    base = {"GEMINI_API_KEY": "test-key"}
    base.update(overrides)
    with patch.dict(os.environ, base, clear=False):
        # Re-import to pick up patched env (avoid module-level singleton)
        from importlib import import_module, reload
        import app.config as cfg_mod
        reload(cfg_mod)
        return cfg_mod.Settings()


def test_default_model_is_flash():
    s = make_settings()
    assert s.gemini_model == "gemini-2.5-flash-lite"


def test_model_switchable_to_pro():
    s = make_settings(GEMINI_MODEL="gemini-2.5-pro")
    assert s.gemini_model == "gemini-2.5-pro"


def test_api_key_read_from_env():
    s = make_settings(GEMINI_API_KEY="abc-123")
    assert s.gemini_api_key == "abc-123"


def test_default_max_policy_size():
    s = make_settings()
    assert s.max_policy_size_kb == 20


def test_max_policy_size_override():
    s = make_settings(MAX_POLICY_SIZE_KB="50")
    assert s.max_policy_size_kb == 50


def test_default_rate_limit():
    # Temporarily clear env override set by conftest for rate-limit bypass
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("RATE_LIMIT_PER_HOUR", None)
        s = make_settings()
    assert s.rate_limit_per_hour == 10


def test_default_app_env():
    s = make_settings()
    assert s.app_env == "development"


def test_database_url_has_default():
    s = make_settings()
    assert "postgresql" in s.database_url
