"""GCP IAM live scanner — uses google-auth AuthorizedSession (no discovery overhead)."""
from __future__ import annotations

import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.ingestion.live_scanners._types import ScanTarget
from app.ingestion.parser import PolicyDoc, Statement

logger = logging.getLogger(__name__)

_ENV_PROJECT_ID = "GCP_PROJECT_ID"
_ENV_KEY_JSON = "GCP_SERVICE_ACCOUNT_KEY_JSON"
_ENV_CREDENTIALS_FILE = "GOOGLE_APPLICATION_CREDENTIALS"

_SCOPES = ["https://www.googleapis.com/auth/cloud-platform.read-only"]

_CRM_BASE = "https://cloudresourcemanager.googleapis.com/v1"
_IAM_BASE = "https://iam.googleapis.com/v1"

# Predefined GCP roles (roles/*) are Google-managed — not user-defined.
# Skip fetching their permission definitions (equivalent to skipping AWS-managed policies).
_PREDEFINED_ROLE_PREFIX = "roles/"


def _is_predefined(role: str) -> bool:
    return role.startswith(_PREDEFINED_ROLE_PREFIX)


def _read_env() -> tuple[str, str | None, str | None]:
    """Returns (project_id, key_json_str_or_None, creds_file_or_None)."""
    project_id = os.environ.get(_ENV_PROJECT_ID, "")
    if not project_id:
        raise ValueError(f"Missing required env var: {_ENV_PROJECT_ID}")
    key_json = os.environ.get(_ENV_KEY_JSON) or None
    creds_file = os.environ.get(_ENV_CREDENTIALS_FILE) or None
    if not key_json and not creds_file:
        raise ValueError(
            f"Missing required env var: {_ENV_KEY_JSON} (or {_ENV_CREDENTIALS_FILE})"
        )
    return project_id, key_json, creds_file


def _build_credentials(key_json: str | None, creds_file: str | None):
    from google.oauth2.service_account import Credentials

    if key_json:
        return Credentials.from_service_account_info(
            json.loads(key_json), scopes=_SCOPES
        )
    return Credentials.from_service_account_file(creds_file, scopes=_SCOPES)  # type: ignore[arg-type]


def _authed_session(credentials):
    from google.auth.transport.requests import AuthorizedSession

    return AuthorizedSession(credentials)


def _fetch_project_bindings(session, project_id: str) -> list[dict]:
    resp = session.post(
        f"{_CRM_BASE}/projects/{project_id}:getIamPolicy", json={}
    )
    resp.raise_for_status()
    return resp.json().get("bindings", [])


def _list_custom_roles(session, project_id: str) -> list[str]:
    """Return full role names for non-deleted custom roles at project level."""
    resp = session.get(f"{_IAM_BASE}/projects/{project_id}/roles", params={"view": "BASIC"})
    if not resp.ok:
        return []
    roles = resp.json().get("roles", [])
    return [r["name"] for r in roles if not r.get("deleted")]


def _fetch_custom_role_permissions(session, role_name: str) -> list[str]:
    resp = session.get(f"{_IAM_BASE}/{role_name}", params={"view": "FULL"})
    if not resp.ok:
        return []
    return resp.json().get("includedPermissions", [])


class GcpScanner:
    """Implements the Scanner protocol for GCP IAM.

    Parallel fetch:
      • project IAM bindings (who has what role)
      • custom project-level role definitions (user-defined roles only)
    Predefined GCP roles (roles/*) are Google-managed — skipped.
    """

    def scan(self, target: ScanTarget) -> PolicyDoc:
        project_id, key_json, creds_file = _read_env()
        credentials = _build_credentials(key_json, creds_file)
        session = _authed_session(credentials)

        try:
            with ThreadPoolExecutor(max_workers=4) as pool:
                f_bindings = pool.submit(_fetch_project_bindings, session, project_id)
                f_roles = pool.submit(_list_custom_roles, session, project_id)

                bindings: list[dict] = f_bindings.result()
                custom_role_names: list[str] = f_roles.result()

                # Fetch custom role permission definitions in parallel
                perm_futures = {
                    pool.submit(_fetch_custom_role_permissions, session, rn): rn
                    for rn in custom_role_names
                }
                custom_role_perms: dict[str, list[str]] = {}
                for f in as_completed(perm_futures):
                    rn = perm_futures[f]
                    try:
                        custom_role_perms[rn] = f.result()
                    except Exception:
                        pass

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
            logger.debug("GCPNormalizer could not parse bindings; using deny-all")

        if not raw_statements:
            return PolicyDoc(
                statement=[Statement(effect="Deny", action=["*"], resource="*")]
            )
        return PolicyDoc(statement=[Statement.model_validate(s) for s in raw_statements])
