"""Dispatcher contract tests for live_scanners package — Batch 5."""
from __future__ import annotations

import pytest
from dataclasses import FrozenInstanceError


# ---------------------------------------------------------------------------
# 1. Dispatcher: get_scanner("aws") returns Scanner-protocol object
# ---------------------------------------------------------------------------

def test_get_scanner_aws_returns_object_with_scan_method():
    from app.ingestion.live_scanners import get_scanner
    scanner = get_scanner("aws")
    assert hasattr(scanner, "scan")
    assert callable(scanner.scan)


# ---------------------------------------------------------------------------
# 2. Dispatcher: unsupported clouds raise NotImplementedError
# ---------------------------------------------------------------------------

def test_get_scanner_azure_returns_scanner():
    """azure now registered in Batch 6 — must not raise."""
    from app.ingestion.live_scanners import get_scanner
    from app.ingestion.live_scanners.azure import AzureScanner
    assert isinstance(get_scanner("azure"), AzureScanner)


def test_get_scanner_gcp_returns_gcp_scanner():
    """gcp now registered in Batch 7 — must not raise."""
    from app.ingestion.live_scanners import get_scanner
    from app.ingestion.live_scanners.gcp import GcpScanner
    assert isinstance(get_scanner("gcp"), GcpScanner)


def test_get_scanner_unknown_raises_not_implemented():
    from app.ingestion.live_scanners import get_scanner
    with pytest.raises(NotImplementedError):
        get_scanner("somecloud")


# ---------------------------------------------------------------------------
# 3. ScanTarget — frozen, correct repr
# ---------------------------------------------------------------------------

def test_scan_target_frozen():
    from app.ingestion.live_scanners._types import ScanTarget
    target = ScanTarget(cloud="aws", role_arn="arn:aws:iam::123456789012:role/Test")
    with pytest.raises(FrozenInstanceError):
        target.role_arn = "other"  # type: ignore[misc]


def test_scan_target_stores_fields():
    from app.ingestion.live_scanners._types import ScanTarget
    target = ScanTarget(cloud="aws", role_arn="arn:aws:iam::123456789012:role/Test")
    assert target.cloud == "aws"
    assert target.role_arn == "arn:aws:iam::123456789012:role/Test"


# ---------------------------------------------------------------------------
# 4. AwsCredentials — frozen + masked repr
# ---------------------------------------------------------------------------

def test_aws_credentials_frozen():
    from app.ingestion.live_scanners._types import AwsCredentials
    creds = AwsCredentials(
        access_key_id="AKIAIOSFODNN7EXAMPLE",
        secret_access_key="wJalrXUtnFEMI/K7MDENG",
    )
    with pytest.raises(FrozenInstanceError):
        creds.secret_access_key = "other"  # type: ignore[misc]


def test_aws_credentials_repr_masks_secret():
    from app.ingestion.live_scanners._types import AwsCredentials
    creds = AwsCredentials(
        access_key_id="AKIAIOSFODNN7EXAMPLE",
        secret_access_key="wJalrXUtnFEMI/K7MDENG",
        session_token="AQoXnyc4lcK4EXAMPLE",
    )
    r = repr(creds)
    assert "wJalrXUtnFEMI/K7MDENG" not in r
    assert "AQoXnyc4lcK4EXAMPLE" not in r
    assert "***" in r


def test_aws_credentials_repr_shows_access_key_id():
    from app.ingestion.live_scanners._types import AwsCredentials
    creds = AwsCredentials(
        access_key_id="AKIAIOSFODNN7EXAMPLE",
        secret_access_key="secret",
    )
    r = repr(creds)
    assert "AKIAIOSFODNN7EXAMPLE" in r


# ---------------------------------------------------------------------------
# 5. AwsScanner importable from new location
# ---------------------------------------------------------------------------

def test_aws_scanner_importable():
    from app.ingestion.live_scanners.aws import AwsScanner
    assert AwsScanner is not None


def test_scan_live_importable_from_new_location():
    from app.ingestion.live_scanners.aws import scan_live
    assert callable(scan_live)
