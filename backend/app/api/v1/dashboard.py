"""GET /api/v1/dashboard/summary — risk aggregate."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.v1.deps import get_current_user
from app.db.database import get_db
from app.db.models import User
from app.db.repository import AnalysisRepository

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/summary")
def dashboard_summary(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> dict:
    repo = AnalysisRepository(db)
    analyses = repo.list_all(limit=1000, offset=0)

    from app.analysis.dashboard import DashboardBuilder
    summary = DashboardBuilder(analyses).build(org_slug=None)
    return summary.to_dict()
