"""GET /analyses and GET /analyses/{id} endpoints."""
from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.v1.deps import get_current_user
from app.db.database import get_db
from app.db.models import User
from app.db.repository import AnalysisRepository

router = APIRouter(prefix="/api/v1/analyses", tags=["analyses"])


class AnalysisSummary(BaseModel):
    id: int
    created_at: datetime
    risk_score: float
    severity: str
    policy_hash: str


class AnalysisDetail(BaseModel):
    id: int
    created_at: datetime
    risk_score: float
    severity: str
    policy_hash: str
    policy_json: str
    findings: list[dict]
    suggestions: dict
    graph_data: dict


class AnalysisListResponse(BaseModel):
    items: list[AnalysisSummary]
    total: int
    limit: int
    offset: int


class AnalysisStatusResponse(BaseModel):
    id: int
    status: str
    task_id: str | None
    result: dict | None


class InheritanceResponse(BaseModel):
    analysis_id: int
    from_node: str
    to_node: str
    lca_node_id: str
    lca_node_type: str
    lca_label: str


class PrivescPathItem(BaseModel):
    source_node: str
    target_node: str
    path_nodes: list[str]
    dangerous_actions: list[str]
    severity: str
    description: str


class PrivescResponse(BaseModel):
    analysis_id: int
    paths: list[PrivescPathItem]
    total_paths: int


@router.get("", response_model=AnalysisListResponse)
def list_analyses(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> AnalysisListResponse:
    repo = AnalysisRepository(db)
    records = repo.list_all(limit=limit, offset=offset)
    total = repo.count()

    items = [
        AnalysisSummary(
            id=r.id,
            created_at=r.created_at,
            risk_score=r.risk_score,
            severity=r.severity,
            policy_hash=r.policy_hash,
        )
        for r in records
    ]
    return AnalysisListResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/{analysis_id}/status", response_model=AnalysisStatusResponse)
def get_analysis_status(
    analysis_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> AnalysisStatusResponse:
    repo = AnalysisRepository(db)
    record = repo.get_by_id(analysis_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found")

    result: dict | None = None
    if record.status == "completed":
        result = {
            "risk_score": record.risk_score,
            "severity": record.severity,
            "findings": json.loads(record.findings_json),
            "suggestions": json.loads(record.suggestions_json),
            "graph_data": json.loads(record.graph_data_json),
        }

    return AnalysisStatusResponse(
        id=record.id,
        status=record.status,
        task_id=record.task_id,
        result=result,
    )


@router.get("/{analysis_id}/inheritance", response_model=InheritanceResponse)
def get_inheritance(
    analysis_id: int,
    from_node: str = Query(...),
    to_node: str = Query(...),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> InheritanceResponse:
    repo = AnalysisRepository(db)
    record = repo.get_by_id(analysis_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found")

    from app.analysis.graph_builder import EdgeData, GraphData, NodeData
    from app.analysis.lca import LCAEngine

    raw = json.loads(record.graph_data_json)
    graph = GraphData(
        nodes=[
            NodeData(
                id=n["id"],
                label=n["label"],
                node_type=n["node_type"],
                metadata=n.get("metadata", {}),
            )
            for n in raw["nodes"]
        ],
        edges=[
            EdgeData(source=e["source"], target=e["target"], edge_type=e["edge_type"])
            for e in raw["edges"]
        ],
    )

    engine = LCAEngine(graph)
    lca_id = engine.lca(from_node, to_node)
    if lca_id is None:
        raise HTTPException(
            status_code=422,
            detail=f"One or both nodes not found in graph: {from_node!r}, {to_node!r}",
        )

    lca_node = next((n for n in graph.nodes if n.id == lca_id), None)
    if lca_node is None:
        raise HTTPException(status_code=500, detail="LCA node missing from graph")

    return InheritanceResponse(
        analysis_id=analysis_id,
        from_node=from_node,
        to_node=to_node,
        lca_node_id=lca_id,
        lca_node_type=lca_node.node_type,
        lca_label=lca_node.label,
    )


@router.get("/{analysis_id}/report")
def get_report(
    analysis_id: int,
    format: str = Query(default="json", pattern="^(json|pdf)$"),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    repo = AnalysisRepository(db)
    record = repo.get_by_id(analysis_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found")

    from app.analysis.graph_builder import EdgeData, GraphData, NodeData
    from app.analysis.report import ReportBuilder

    raw = json.loads(record.graph_data_json)
    graph = GraphData(
        nodes=[
            NodeData(
                id=n["id"],
                label=n["label"],
                node_type=n["node_type"],
                metadata=n.get("metadata", {}),
            )
            for n in raw["nodes"]
        ],
        edges=[
            EdgeData(source=e["source"], target=e["target"], edge_type=e["edge_type"])
            for e in raw["edges"]
        ],
    )

    findings = json.loads(record.findings_json)
    suggestions = json.loads(record.suggestions_json)
    policy = json.loads(record.policy_json)

    # Run all compliance frameworks for the report
    compliance_results: dict = {}
    try:
        from app.analysis.compliance import ComplianceChecker, SUPPORTED_FRAMEWORKS
        from app.analysis.privesc import PrivescDetector as _PD
        _privesc = [
            {
                "source_node": p.source_node,
                "target_node": p.target_node,
                "path_nodes": p.path_nodes,
                "dangerous_actions": p.dangerous_actions,
                "severity": p.severity,
                "description": p.description,
            }
            for p in _PD(graph).detect()
        ]
        checker = ComplianceChecker(
            analysis_id=analysis_id,
            policy=policy,
            findings=findings,
            privesc_paths=_privesc,
            graph=graph,
            risk_score=record.risk_score,
            severity=record.severity,
        )
        for fw in SUPPORTED_FRAMEWORKS:
            try:
                compliance_results[fw] = checker.check(fw).to_dict()
            except Exception:
                pass
    except Exception:
        pass

    builder = ReportBuilder(
        analysis_id=analysis_id,
        graph=graph,
        findings=findings,
        suggestions=suggestions,
        risk_score=record.risk_score,
        severity=record.severity,
        created_at=record.created_at.isoformat(),
        policy=policy,
        compliance_results=compliance_results,
    )
    report = builder.build()

    if format == "pdf":
        pdf_bytes = report.render_pdf()
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="analysis_{analysis_id}_report.pdf"'
            },
        )

    return report.to_dict()


@router.get("/{analysis_id}/privesc", response_model=PrivescResponse)
def get_privesc(
    analysis_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> PrivescResponse:
    repo = AnalysisRepository(db)
    record = repo.get_by_id(analysis_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found")

    from app.analysis.graph_builder import EdgeData, GraphData, NodeData
    from app.analysis.privesc import PrivescDetector

    raw = json.loads(record.graph_data_json)
    graph = GraphData(
        nodes=[
            NodeData(
                id=n["id"],
                label=n["label"],
                node_type=n["node_type"],
                metadata=n.get("metadata", {}),
            )
            for n in raw["nodes"]
        ],
        edges=[
            EdgeData(source=e["source"], target=e["target"], edge_type=e["edge_type"])
            for e in raw["edges"]
        ],
    )

    detector = PrivescDetector(graph)
    paths = detector.detect()

    items = [
        PrivescPathItem(
            source_node=p.source_node,
            target_node=p.target_node,
            path_nodes=p.path_nodes,
            dangerous_actions=p.dangerous_actions,
            severity=p.severity,
            description=p.description,
        )
        for p in paths
    ]
    return PrivescResponse(analysis_id=analysis_id, paths=items, total_paths=len(items))


@router.get("/{analysis_id}/compliance")
def get_compliance(
    analysis_id: int,
    framework: str = Query(..., pattern="^(cis|nist|soc2|pci|iso27001)$"),
    format: str = Query(default="json", pattern="^(json|xlsx)$"),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    repo = AnalysisRepository(db)
    record = repo.get_by_id(analysis_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found")

    from app.analysis.compliance import ComplianceChecker
    from app.analysis.graph_builder import EdgeData, GraphData, NodeData
    from app.analysis.privesc import PrivescDetector

    raw = json.loads(record.graph_data_json)
    graph = GraphData(
        nodes=[
            NodeData(
                id=n["id"],
                label=n["label"],
                node_type=n["node_type"],
                metadata=n.get("metadata", {}),
            )
            for n in raw["nodes"]
        ],
        edges=[
            EdgeData(source=e["source"], target=e["target"], edge_type=e["edge_type"])
            for e in raw["edges"]
        ],
    )

    privesc_paths = [
        {
            "source_node": p.source_node,
            "target_node": p.target_node,
            "path_nodes": p.path_nodes,
            "dangerous_actions": p.dangerous_actions,
            "severity": p.severity,
            "description": p.description,
        }
        for p in PrivescDetector(graph).detect()
    ]

    policy = json.loads(record.policy_json)
    findings = json.loads(record.findings_json)

    checker = ComplianceChecker(
        analysis_id=analysis_id,
        policy=policy,
        findings=findings,
        privesc_paths=privesc_paths,
        graph=graph,
        risk_score=record.risk_score,
        severity=record.severity,
    )
    report = checker.check(framework)

    if format == "xlsx":
        xlsx_bytes = report.render_xlsx()
        return Response(
            content=xlsx_bytes,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="compliance_{analysis_id}_{framework}.xlsx"'
                )
            },
        )

    return report.to_dict()


@router.get("/{analysis_id}", response_model=AnalysisDetail)
def get_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> AnalysisDetail:
    repo = AnalysisRepository(db)
    record = repo.get_by_id(analysis_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found")

    return AnalysisDetail(
        id=record.id,
        created_at=record.created_at,
        risk_score=record.risk_score,
        severity=record.severity,
        policy_hash=record.policy_hash,
        policy_json=record.policy_json,
        findings=json.loads(record.findings_json),
        suggestions=json.loads(record.suggestions_json),
        graph_data=json.loads(record.graph_data_json),
    )
