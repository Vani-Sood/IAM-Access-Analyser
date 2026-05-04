"""GCP IAM live scanner — enumerates project IAM bindings via Cloud IAM API."""
from __future__ import annotations

import json
import logging
import os

from app.ingestion.live_scanners._types import ScanTarget
from app.ingestion.parser import PolicyDoc, Statement

logger = logging.getLogger(__name__)

_ENV_PROJECT_ID = "GCP_PROJECT_ID"
_ENV_KEY_JSON = "GCP_SERVICE_ACCOUNT_KEY_JSON"
_ENV_CREDENTIALS_FILE = "GOOGLE_APPLICATION_CREDENTIALS"

_SCOPES = ["https://www.googleapis.com/auth/cloud-platform.read-only"]


def _read_env() -> tuple[str, str]:
    """Read and validate GCP env vars.

    Returns (project_id, service_account_key_json).
    Raises ValueError listing missing var names (no secret values in message).
    """
    project_id = os.environ.get(_ENV_PROJECT_ID, "")
    if not project_id:
        raise ValueError(
            f"Missing required env var: {_ENV_PROJECT_ID}"
        )

    key_json = os.environ.get(_ENV_KEY_JSON, "")
    creds_file = os.environ.get(_ENV_CREDENTIALS_FILE, "")
    if not key_json and not creds_file:
        raise ValueError(
            f"Missing required env var: {_ENV_KEY_JSON} "
            f"(or {_ENV_CREDENTIALS_FILE})"
        )

    return project_id, key_json


def _build_credentials(key_json: str):
    """Build google-auth Credentials from JSON string or application default."""
    from google.oauth2.service_account import Credentials  # type: ignore
    info = json.loads(key_json)
    return Credentials.from_service_account_info(info, scopes=_SCOPES)


class GcpScanner:
    """Implements the Scanner protocol for GCP IAM via service-account auth."""

    def scan(self, target: ScanTarget) -> PolicyDoc:
        project_id, key_json = _read_env()

        try:
            from googleapiclient.discovery import build  # type: ignore

            credentials = _build_credentials(key_json)
            service = build(
                "cloudresourcemanager", "v1", credentials=credentials
            )

            response = (
                service.projects()
                .getIamPolicy(resource=project_id, body={})
                .execute()
            )
            bindings: list[dict] = response.get("bindings") or []

        except ValueError:
            raise
        except Exception as exc:
            raise RuntimeError(f"GCP scan failed: {exc}") from exc

        if not bindings:
            return PolicyDoc(
                statement=[Statement(effect="Deny", action=["*"], resource="*")]
            )

        from app.ingestion.normalizers.gcp import GCPNormalizer

        raw_statements: list[dict] = []
        try:
            doc = GCPNormalizer().normalize({"bindings": bindings})
            for stmt in doc.statement:
                raw_statements.append(stmt.model_dump(by_alias=True))
        except Exception:
            logger.debug(
                "GCPNormalizer could not parse bindings; using deny-all"
            )

        if not raw_statements:
            return PolicyDoc(
                statement=[Statement(effect="Deny", action=["*"], resource="*")]
            )
        return PolicyDoc(
            statement=[Statement.model_validate(s) for s in raw_statements]
        )
