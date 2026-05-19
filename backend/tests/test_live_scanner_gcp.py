"""GCP live scanner tests — Batch 7.

All GCP SDK calls are mocked; no real GCP credentials needed.
"""
from __future__ import annotations

import os
from dataclasses import FrozenInstanceError
from unittest.mock import MagicMock, patch

import pytest

from app.ingestion.parser import PolicyDoc


# ---------------------------------------------------------------------------
# 1. GcpCredentials — frozen + masked repr
# ---------------------------------------------------------------------------

def test_gcp_credentials_frozen():
    from app.ingestion.live_scanners._types import GcpCredentials
    creds = GcpCredentials(
        project_id="my-project",
        service_account_key_json='{"type": "service_account"}',
    )
    with pytest.raises(FrozenInstanceError):
        creds.project_id = "other"  # type: ignore[misc]


def test_gcp_credentials_repr_masks_key_json():
    from app.ingestion.live_scanners._types import GcpCredentials
    secret_json = '{"private_key": "VERY_SECRET_KEY_VALUE"}'
    creds = GcpCredentials(
        project_id="my-project",
        service_account_key_json=secret_json,
    )
    r = repr(creds)
    assert "VERY_SECRET_KEY_VALUE" not in r
    assert "***" in r
    assert "my-project" in r


def test_gcp_credentials_stores_fields():
    from app.ingestion.live_scanners._types import GcpCredentials
    creds = GcpCredentials(
        project_id="proj-123",
        service_account_key_json='{"type": "service_account"}',
    )
    assert creds.project_id == "proj-123"
    assert creds.service_account_key_json == '{"type": "service_account"}'


# ---------------------------------------------------------------------------
# 2. Dispatcher resolves gcp
# ---------------------------------------------------------------------------

def test_get_scanner_gcp_returns_gcp_scanner():
    from app.ingestion.live_scanners import get_scanner
    from app.ingestion.live_scanners.gcp import GcpScanner
    scanner = get_scanner("gcp")
    assert isinstance(scanner, GcpScanner)


# ---------------------------------------------------------------------------
# 3. Missing env vars → ValueError before SDK call
# ---------------------------------------------------------------------------

def test_gcp_scanner_raises_on_missing_env(monkeypatch):
    monkeypatch.delenv("GCP_PROJECT_ID", raising=False)
    monkeypatch.delenv("GCP_SERVICE_ACCOUNT_KEY_JSON", raising=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)

    from app.ingestion.live_scanners.gcp import GcpScanner
    from app.ingestion.live_scanners._types import ScanTarget

    scanner = GcpScanner()
    with pytest.raises(ValueError, match="GCP_PROJECT_ID"):
        scanner.scan(ScanTarget(cloud="gcp"))


def test_gcp_scanner_raises_on_missing_project_id(monkeypatch):
    monkeypatch.delenv("GCP_PROJECT_ID", raising=False)
    monkeypatch.setenv(
        "GCP_SERVICE_ACCOUNT_KEY_JSON",
        '{"type": "service_account"}',
    )

    from app.ingestion.live_scanners.gcp import GcpScanner
    from app.ingestion.live_scanners._types import ScanTarget

    scanner = GcpScanner()
    with pytest.raises(ValueError, match="GCP_PROJECT_ID"):
        scanner.scan(ScanTarget(cloud="gcp"))


def test_gcp_scanner_raises_on_missing_credentials(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT_ID", "my-project")
    monkeypatch.delenv("GCP_SERVICE_ACCOUNT_KEY_JSON", raising=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)

    from app.ingestion.live_scanners.gcp import GcpScanner
    from app.ingestion.live_scanners._types import ScanTarget

    scanner = GcpScanner()
    with pytest.raises(ValueError, match="GCP_SERVICE_ACCOUNT_KEY_JSON"):
        scanner.scan(ScanTarget(cloud="gcp"))


def test_gcp_scanner_error_does_not_leak_secret(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT_ID", "my-project")
    secret_value = "ULTRA_SECRET_KEY_JSON_VALUE"
    monkeypatch.setenv("GCP_SERVICE_ACCOUNT_KEY_JSON", secret_value)
    # Provide bad JSON so from_service_account_info raises ValueError,
    # which surfaces through _read_env — but we only care that the raw
    # env var value is not echoed in the error message itself.
    # Here we test the env-validation path: remove project id to trigger
    # the ValueError before any SDK call.
    monkeypatch.delenv("GCP_PROJECT_ID", raising=False)

    from app.ingestion.live_scanners.gcp import GcpScanner
    from app.ingestion.live_scanners._types import ScanTarget

    scanner = GcpScanner()
    with pytest.raises(ValueError) as exc_info:
        scanner.scan(ScanTarget(cloud="gcp"))
    assert secret_value not in str(exc_info.value)


# ---------------------------------------------------------------------------
# 4. Happy path — returns PolicyDoc with expected bindings
# ---------------------------------------------------------------------------

def _make_mock_iam_response(
    bindings: list[dict] | None = None,
) -> dict:
    if bindings is None:
        bindings = [{"role": "roles/viewer", "members": ["user:alice@example.com"]}]
    return {"bindings": bindings, "etag": "ACAB", "version": 1}


def _make_mock_session(iam_response: dict) -> MagicMock:
    """Return a mock AuthorizedSession matching the new scanner API."""
    mock_session = MagicMock()
    post_resp = MagicMock()
    post_resp.raise_for_status = MagicMock()
    post_resp.json.return_value = iam_response
    mock_session.post.return_value = post_resp
    get_resp = MagicMock()
    get_resp.ok = True
    get_resp.json.return_value = {"roles": []}
    mock_session.get.return_value = get_resp
    return mock_session


def test_gcp_scanner_happy_path(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT_ID", "my-project")
    monkeypatch.setenv(
        "GCP_SERVICE_ACCOUNT_KEY_JSON",
        '{"type": "service_account", "project_id": "my-project"}',
    )

    mock_session = _make_mock_session(_make_mock_iam_response())

    with (
        patch("app.ingestion.live_scanners.gcp._build_credentials", return_value=MagicMock()),
        patch("app.ingestion.live_scanners.gcp._authed_session", return_value=mock_session),
    ):
        from app.ingestion.live_scanners.gcp import GcpScanner
        from app.ingestion.live_scanners._types import ScanTarget

        result = GcpScanner().scan(ScanTarget(cloud="gcp"))

    assert isinstance(result, PolicyDoc)
    all_actions = [a for stmt in result.statement for a in stmt.actions]
    assert "roles/viewer" in all_actions


def test_gcp_scanner_happy_path_multiple_bindings(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT_ID", "my-project")
    monkeypatch.setenv(
        "GCP_SERVICE_ACCOUNT_KEY_JSON",
        '{"type": "service_account", "project_id": "my-project"}',
    )

    bindings = [
        {"role": "roles/viewer", "members": ["user:alice@example.com"]},
        {"role": "roles/editor", "members": ["user:bob@example.com"]},
    ]
    mock_session = _make_mock_session(_make_mock_iam_response(bindings))

    with (
        patch("app.ingestion.live_scanners.gcp._build_credentials", return_value=MagicMock()),
        patch("app.ingestion.live_scanners.gcp._authed_session", return_value=mock_session),
    ):
        from app.ingestion.live_scanners.gcp import GcpScanner
        from app.ingestion.live_scanners._types import ScanTarget

        result = GcpScanner().scan(ScanTarget(cloud="gcp"))

    assert isinstance(result, PolicyDoc)
    all_actions = [a for stmt in result.statement for a in stmt.actions]
    assert "roles/viewer" in all_actions
    assert "roles/editor" in all_actions


# ---------------------------------------------------------------------------
# 5. SDK exception → RuntimeError
# ---------------------------------------------------------------------------

def test_gcp_scanner_wraps_sdk_exception(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT_ID", "my-project")
    monkeypatch.setenv(
        "GCP_SERVICE_ACCOUNT_KEY_JSON",
        '{"type": "service_account", "project_id": "my-project"}',
    )

    with (
        patch("app.ingestion.live_scanners.gcp._build_credentials", return_value=MagicMock()),
        patch("app.ingestion.live_scanners.gcp._authed_session", return_value=MagicMock()),
        patch(
            "app.ingestion.live_scanners.gcp._fetch_project_bindings",
            side_effect=Exception("GCP API unreachable"),
        ),
    ):
        from app.ingestion.live_scanners.gcp import GcpScanner
        from app.ingestion.live_scanners._types import ScanTarget

        with pytest.raises(RuntimeError, match="GCP scan failed"):
            GcpScanner().scan(ScanTarget(cloud="gcp"))


def test_gcp_scanner_wraps_api_call_exception(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT_ID", "my-project")
    monkeypatch.setenv(
        "GCP_SERVICE_ACCOUNT_KEY_JSON",
        '{"type": "service_account", "project_id": "my-project"}',
    )

    mock_session = MagicMock()
    mock_session.post.side_effect = Exception("API quota exceeded")

    with (
        patch("app.ingestion.live_scanners.gcp._build_credentials", return_value=MagicMock()),
        patch("app.ingestion.live_scanners.gcp._authed_session", return_value=mock_session),
    ):
        from app.ingestion.live_scanners.gcp import GcpScanner
        from app.ingestion.live_scanners._types import ScanTarget

        with pytest.raises(RuntimeError, match="GCP scan failed"):
            GcpScanner().scan(ScanTarget(cloud="gcp"))


# ---------------------------------------------------------------------------
# 6. Empty project → deny-all fallback
# ---------------------------------------------------------------------------

def test_gcp_scanner_empty_bindings_returns_deny_all(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT_ID", "my-project")
    monkeypatch.setenv(
        "GCP_SERVICE_ACCOUNT_KEY_JSON",
        '{"type": "service_account", "project_id": "my-project"}',
    )

    mock_session = _make_mock_session({"bindings": [], "etag": "ACAB"})

    with (
        patch("app.ingestion.live_scanners.gcp._build_credentials", return_value=MagicMock()),
        patch("app.ingestion.live_scanners.gcp._authed_session", return_value=mock_session),
    ):
        from app.ingestion.live_scanners.gcp import GcpScanner
        from app.ingestion.live_scanners._types import ScanTarget

        result = GcpScanner().scan(ScanTarget(cloud="gcp"))

    assert isinstance(result, PolicyDoc)
    assert len(result.statement) == 1
    assert result.statement[0].effect.value == "Deny"


def test_gcp_scanner_no_bindings_key_returns_deny_all(monkeypatch):
    """Response missing 'bindings' key entirely → deny-all fallback."""
    monkeypatch.setenv("GCP_PROJECT_ID", "my-project")
    monkeypatch.setenv(
        "GCP_SERVICE_ACCOUNT_KEY_JSON",
        '{"type": "service_account", "project_id": "my-project"}',
    )

    mock_session = _make_mock_session({"etag": "ACAB"})

    with (
        patch("app.ingestion.live_scanners.gcp._build_credentials", return_value=MagicMock()),
        patch("app.ingestion.live_scanners.gcp._authed_session", return_value=mock_session),
    ):
        from app.ingestion.live_scanners.gcp import GcpScanner
        from app.ingestion.live_scanners._types import ScanTarget

        result = GcpScanner().scan(ScanTarget(cloud="gcp"))

    assert isinstance(result, PolicyDoc)
    assert len(result.statement) == 1
    assert result.statement[0].effect.value == "Deny"
