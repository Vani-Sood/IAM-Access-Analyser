"""Shared frozen dataclasses for the live-scanner package."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanTarget:
    """What to scan: which cloud and which credential anchor (e.g. role ARN)."""

    cloud: str
    role_arn: str | None = None


@dataclass(frozen=True)
class AwsCredentials:
    """Temporary AWS credentials — secret fields masked in repr."""

    access_key_id: str
    secret_access_key: str
    session_token: str | None = None

    def __repr__(self) -> str:
        masked_token = "***" if self.session_token else None
        return (
            f"AwsCredentials("
            f"access_key_id={self.access_key_id!r}, "
            f"secret_access_key='***', "
            f"session_token={masked_token!r})"
        )


@dataclass(frozen=True)
class AzureCredentials:
    """Azure service-principal credentials — client_secret masked in repr."""

    tenant_id: str
    client_id: str
    client_secret: str
    subscription_id: str

    def __repr__(self) -> str:
        return (
            f"AzureCredentials("
            f"tenant_id={self.tenant_id!r}, "
            f"client_id={self.client_id!r}, "
            f"client_secret='***', "
            f"subscription_id={self.subscription_id!r})"
        )


@dataclass(frozen=True)
class GcpCredentials:
    """GCP service-account credentials — key JSON masked in repr."""

    project_id: str
    service_account_key_json: str

    def __repr__(self) -> str:
        return (
            f"GcpCredentials("
            f"project_id={self.project_id!r}, "
            f"service_account_key_json='***')"
        )
