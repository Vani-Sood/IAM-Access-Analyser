"""POST /analyze endpoint — enqueues async Celery task, returns task_id."""
from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ValidationError, field_validator, model_validator
from sqlalchemy.orm import Session

from app.api.v1.deps import get_current_user, resolve_org_membership
from app.config import Settings
from app.db.database import get_db
from app.db.models import User
from app.db.repository import AnalysisRepository
from app.ingestion.parser import PolicyDoc, PolicyValidationError
from app.rate_limiter import limiter

router = APIRouter(prefix="/api/v1/analyze", tags=["analyze"])
logger = logging.getLogger(__name__)

_ARN_RE = re.compile(r"^arn:aws:iam::\d{12}:role/[\w+=,.@/-]{1,512}$")


class AnalyzeRequest(BaseModel):
    mode: Literal["json", "live"] = "json"
    cloud: Literal["aws", "azure", "gcp", "oci", "alibaba", "auto"] = "auto"
    policy: dict | None = None
    role_arn: str | None = None

    @field_validator("role_arn")
    @classmethod
    def validate_role_arn(cls, v: str | None) -> str | None:
        if v is not None and not _ARN_RE.fullmatch(v):
            raise ValueError("Invalid role_arn format — expected arn:aws:iam::<account_id>:role/<name>")
        return v

    @model_validator(mode="after")
    def check(self) -> "AnalyzeRequest":
        if self.mode == "json" and self.policy is None:
            raise ValueError("'policy' required when mode='json'")
        return self


class AnalyzeResponse(BaseModel):
    id: int
    task_id: str
    status: str


def _rate_limit() -> str:
    return f"{Settings().rate_limit_per_hour}/hour"


def _normalize_policy(cloud: str, raw: dict) -> dict:
    """Normalize cloud-specific policy format to AWS PolicyDoc-compatible dict.

    Returns a dict that PolicyDoc.model_validate() can parse.
    Raises HTTPException(422) on invalid input.
    """
    if cloud == "auto":
        from app.ingestion.normalizers.detect import detect_cloud
        detected = detect_cloud(raw)
        if detected is None:
            raise HTTPException(
                status_code=422,
                detail=(
                    "Could not detect cloud provider from policy shape. "
                    "Expected AWS (Statement), GCP (bindings/includedPermissions), "
                    "or Azure (Actions/DataActions) format."
                ),
            )
        cloud = detected

    if cloud == "aws":
        try:
            PolicyDoc.model_validate(raw)
        except (ValidationError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return raw

    try:
        if cloud == "azure":
            from app.ingestion.normalizers.azure import AzureNormalizer
            doc = AzureNormalizer().normalize(raw)
        elif cloud == "oci":
            from app.ingestion.normalizers.oci import OCINormalizer
            doc = OCINormalizer().normalize(raw)
        elif cloud == "alibaba":
            from app.ingestion.normalizers.alibaba import AlibabaNormalizer
            doc = AlibabaNormalizer().normalize(raw)
        else:  # gcp
            from app.ingestion.normalizers.gcp import GCPNormalizer
            doc = GCPNormalizer().normalize(raw)
    except (PolicyValidationError, ValueError, KeyError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return doc.model_dump(by_alias=True, exclude_none=True)


@router.post("", response_model=AnalyzeResponse)
@limiter.limit(_rate_limit)
def analyze_policy(
    request: Request,
    req: AnalyzeRequest,
    x_org_slug: str | None = Header(default=None, alias="X-Org-Slug"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AnalyzeResponse:
    # Resolve org context (raises 404/403 if slug invalid or non-member)
    membership = resolve_org_membership(x_org_slug, current_user, db)
    org_id: int | None = membership.org_id if membership else None

    if req.mode == "json":
        normalized = _normalize_policy(req.cloud, req.policy)  # type: ignore[arg-type]
        policy_for_worker = normalized
        policy_raw_for_hash: dict = normalized
    else:
        policy_for_worker = None
        policy_raw_for_hash = {"role_arn": req.role_arn}

    policy_json_str = json.dumps(policy_raw_for_hash, sort_keys=True)
    policy_hash = hashlib.sha256(policy_json_str.encode()).hexdigest()[:64]

    repo = AnalysisRepository(db)
    record = repo.create(
        policy_hash=policy_hash,
        policy_json=policy_json_str,
        risk_score=0.0,
        severity="pending",
        findings_json="[]",
        suggestions_json="{}",
        graph_data_json='{"nodes":[],"edges":[]}',
        status="pending",
        org_id=org_id,
    )
    db.commit()

    from app.worker.tasks import analyze_policy_task
    task = analyze_policy_task.delay(
        record.id,
        req.mode,
        policy_for_worker,
        req.role_arn,
        req.cloud,
    )

    repo.update_task_id(record.id, task.id)
    db.commit()

    try:
        from app.analysis.audit import AuditLogger
        AuditLogger(db).log(
            "analyze.create",
            {"analysis_id": record.id, "mode": req.mode, "cloud": req.cloud},
            actor_id=current_user.id,
            actor_email=current_user.email,
        )
        db.commit()
    except Exception:
        pass

    return AnalyzeResponse(id=record.id, task_id=task.id, status="pending")
