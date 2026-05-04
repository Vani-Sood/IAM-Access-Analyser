"""GET /api/v1/dashboard/summary — org-wide risk aggregate."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header
from sqlalchemy.orm import Session

from app.api.v1.deps import get_current_user, resolve_org_membership
from app.db.database import get_db
from app.db.models import User
from app.db.repository import AnalysisRepository

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/summary")
def dashboard_summary(
    x_org_slug: str | None = Header(default=None, alias="X-Org-Slug"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    membership = resolve_org_membership(x_org_slug, current_user, db)

    repo = AnalysisRepository(db)
    if membership is not None:
        analyses = repo.list_by_org(membership.org_id, limit=1000, offset=0)
        org_slug = x_org_slug
    else:
        analyses = repo.list_all(limit=1000, offset=0)
        org_slug = None

    from app.analysis.dashboard import DashboardBuilder
    summary = DashboardBuilder(analyses).build(org_slug=org_slug)
    return summary.to_dict()
