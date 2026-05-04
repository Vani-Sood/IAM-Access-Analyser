"""Repository for Analysis persistence."""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import Analysis


class AnalysisRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(
        self,
        *,
        policy_hash: str,
        policy_json: str,
        risk_score: float,
        severity: str,
        findings_json: str,
        suggestions_json: str,
        graph_data_json: str,
        status: str = "completed",
        task_id: str | None = None,
        org_id: int | None = None,
    ) -> Analysis:
        record = Analysis(
            policy_hash=policy_hash,
            policy_json=policy_json,
            risk_score=risk_score,
            severity=severity,
            findings_json=findings_json,
            suggestions_json=suggestions_json,
            graph_data_json=graph_data_json,
            status=status,
            task_id=task_id,
            org_id=org_id,
        )
        self._session.add(record)
        self._session.flush()
        self._session.refresh(record)
        return record

    def get_by_id(self, analysis_id: int) -> Analysis | None:
        return self._session.get(Analysis, analysis_id)

    def update_status(self, analysis_id: int, status: str) -> None:
        record = self._session.get(Analysis, analysis_id)
        if record:
            record.status = status

    def update_task_id(self, analysis_id: int, task_id: str) -> None:
        record = self._session.get(Analysis, analysis_id)
        if record:
            record.task_id = task_id

    def update_results(
        self,
        analysis_id: int,
        *,
        risk_score: float,
        severity: str,
        findings_json: str,
        suggestions_json: str,
        graph_data_json: str,
    ) -> None:
        record = self._session.get(Analysis, analysis_id)
        if record:
            record.risk_score = risk_score
            record.severity = severity
            record.findings_json = findings_json
            record.suggestions_json = suggestions_json
            record.graph_data_json = graph_data_json
            record.status = "completed"

    def list_all(self, *, limit: int = 20, offset: int = 0) -> list[Analysis]:
        """Return personal (org_id IS NULL) analyses."""
        stmt = (
            select(Analysis)
            .where(Analysis.org_id.is_(None))
            .order_by(Analysis.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self._session.scalars(stmt))

    def count(self) -> int:
        """Count personal (org_id IS NULL) analyses."""
        stmt = select(func.count()).select_from(Analysis).where(Analysis.org_id.is_(None))
        return self._session.scalar(stmt) or 0

    def list_by_org(self, org_id: int, *, limit: int = 20, offset: int = 0) -> list[Analysis]:
        stmt = (
            select(Analysis)
            .where(Analysis.org_id == org_id)
            .order_by(Analysis.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self._session.scalars(stmt))

    def count_by_org(self, org_id: int) -> int:
        stmt = (
            select(func.count())
            .select_from(Analysis)
            .where(Analysis.org_id == org_id)
        )
        return self._session.scalar(stmt) or 0

    def set_org_id(self, analysis_id: int, org_id: int | None) -> None:
        record = self._session.get(Analysis, analysis_id)
        if record:
            record.org_id = org_id
