"""Enterprise dashboard aggregator: org-wide risk, trend, service heatmap."""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.db.models import Analysis


@dataclass
class SeverityDistribution:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    def to_dict(self) -> dict:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.info,
        }


@dataclass
class TrendPoint:
    date: str
    count: int
    avg_risk: float

    def to_dict(self) -> dict:
        return {"date": self.date, "count": self.count, "avg_risk": self.avg_risk}


@dataclass
class HeatmapEntry:
    service: str
    action: str
    count: int

    def to_dict(self) -> dict:
        return {"service": self.service, "action": self.action, "count": self.count}


@dataclass
class DashboardSummary:
    org_slug: str | None
    total_analyses: int
    avg_risk_score: float
    severity_distribution: SeverityDistribution
    trend: list[TrendPoint] = field(default_factory=list)
    heatmap: list[HeatmapEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "org_slug": self.org_slug,
            "total_analyses": self.total_analyses,
            "avg_risk_score": self.avg_risk_score,
            "severity_distribution": self.severity_distribution.to_dict(),
            "trend": [t.to_dict() for t in self.trend],
            "heatmap": [h.to_dict() for h in self.heatmap],
        }


class DashboardBuilder:
    _SEVERITIES = ("critical", "high", "medium", "low", "info")

    def __init__(self, analyses: list[Analysis]) -> None:
        self._analyses = analyses

    def build(self, org_slug: str | None = None) -> DashboardSummary:
        analyses = self._analyses
        total = len(analyses)

        avg_risk = round(sum(a.risk_score for a in analyses) / total, 2) if total else 0.0
        severity_dist = self._build_severity_dist(analyses)
        trend = self._build_trend(analyses)
        heatmap = self._build_heatmap(analyses)

        return DashboardSummary(
            org_slug=org_slug,
            total_analyses=total,
            avg_risk_score=avg_risk,
            severity_distribution=severity_dist,
            trend=trend,
            heatmap=heatmap,
        )

    def _build_severity_dist(self, analyses: list[Analysis]) -> SeverityDistribution:
        counts: dict[str, int] = {s: 0 for s in self._SEVERITIES}
        for a in analyses:
            key = a.severity.lower()
            if key in counts:
                counts[key] += 1
        return SeverityDistribution(**counts)

    def _build_trend(self, analyses: list[Analysis]) -> list[TrendPoint]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        day_scores: dict[str, list[float]] = {}
        for a in analyses:
            ts = a.created_at
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts < cutoff:
                continue
            day = ts.strftime("%Y-%m-%d")
            day_scores.setdefault(day, []).append(a.risk_score)

        return [
            TrendPoint(
                date=day,
                count=len(scores),
                avg_risk=round(sum(scores) / len(scores), 2),
            )
            for day, scores in sorted(day_scores.items())
        ]

    def _build_heatmap(self, analyses: list[Analysis]) -> list[HeatmapEntry]:
        counter: Counter = Counter()
        for a in analyses:
            try:
                policy = json.loads(a.policy_json)
            except (json.JSONDecodeError, TypeError):
                continue
            if "Statement" not in policy:
                continue
            for stmt in policy.get("Statement", []):
                raw = stmt.get("Action", [])
                actions: list[str] = [raw] if isinstance(raw, str) else raw
                for action in actions:
                    if not isinstance(action, str) or action == "*":
                        continue
                    parts = action.split(":", 1)
                    if len(parts) == 2:
                        svc = parts[0].lower()
                        act = action.lower()
                        counter[(svc, act)] += 1

        return [
            HeatmapEntry(service=svc, action=act, count=cnt)
            for (svc, act), cnt in counter.most_common(20)
        ]
