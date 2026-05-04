"""Live scanner package — Scanner Protocol + cloud dispatcher."""
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from app.ingestion.live_scanners._types import ScanTarget
    from app.ingestion.parser import PolicyDoc


@runtime_checkable
class Scanner(Protocol):
    def scan(self, target: "ScanTarget") -> "PolicyDoc": ...


def get_scanner(cloud: str) -> Scanner:
    """Return the Scanner implementation for *cloud*.

    Raises NotImplementedError for any cloud without a live scanner.
    """
    if cloud == "aws":
        from app.ingestion.live_scanners.aws import AwsScanner
        return AwsScanner()
    if cloud == "azure":
        from app.ingestion.live_scanners.azure import AzureScanner
        return AzureScanner()
    if cloud == "gcp":
        from app.ingestion.live_scanners.gcp import GcpScanner
        return GcpScanner()
    raise NotImplementedError(
        f"Live scanner for {cloud!r} not yet implemented"
    )
