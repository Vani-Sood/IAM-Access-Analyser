"""Celery tasks for async IAM policy analysis."""
from __future__ import annotations

import json
import logging

from app.worker.celery_app import celery

logger = logging.getLogger(__name__)


def run_analysis(
    analysis_id: int,
    mode: str,
    policy_data: dict | None,
    role_arn: str | None,
    *,
    cloud: str = "aws",
    db_session=None,
) -> None:
    """Full analysis pipeline. Separated from task for testability.

    If db_session is None, creates and manages its own session.
    """
    owns_session = db_session is None
    if owns_session:
        from app.db.database import _get_session_factory
        db_session = _get_session_factory()()

    from app.db.repository import AnalysisRepository
    repo = AnalysisRepository(db_session)

    try:
        repo.update_status(analysis_id, "running")
        db_session.commit()

        if mode == "live":
            if cloud == "gcp":
                from app.ingestion.live_scanners.gcp import GcpScanner
                from app.ingestion.live_scanners._types import ScanTarget
                policy = GcpScanner().scan(ScanTarget(cloud="gcp"))
            elif cloud == "azure":
                from app.ingestion.live_scanners.azure import AzureScanner
                from app.ingestion.live_scanners._types import ScanTarget
                policy = AzureScanner().scan(ScanTarget(cloud="azure"))
            else:
                from app.ingestion.live_scanners.aws import scan_live
                policy = scan_live(role_arn)
        elif mode == "json" and policy_data is not None:
            from pydantic import ValidationError
            from app.ingestion.parser import PolicyDoc
            policy = PolicyDoc.model_validate(policy_data)
        else:
            raise ValueError(f"Invalid mode or missing data: mode={mode!r}")

        from app.analysis.findings import generate_findings
        from app.analysis.graph_builder import build_graph
        from app.analysis.risk_scorer import get_severity, score_policy
        from app.ingestion.expander import expand_wildcards

        # For live scans the placeholder {"role_arn": ...} was stored at creation.
        # Overwrite with the real policy so the heatmap can aggregate it.
        # exclude_none=True avoids null optional fields polluting compliance checks.
        real_policy_json: str | None = None
        if mode == "live":
            real_policy_json = json.dumps(
                policy.model_dump(by_alias=True, exclude_none=True), sort_keys=True
            )

        expanded = expand_wildcards(policy)
        risk_score = score_policy(policy)
        severity = get_severity(risk_score)
        findings = generate_findings(policy)
        graph = build_graph(expanded)

        from app.ai.context_builder import build_suggestion_prompt
        from app.ai.llm_client import call_llm
        from app.ai.validator import validate_llm_output
        from app.ingestion.catalog import get_all_actions

        valid_actions = set(get_all_actions())
        system_prompt, user_prompt = build_suggestion_prompt(policy, findings, list(valid_actions))
        try:
            raw_llm = call_llm(system_prompt, user_prompt)
            suggestions = validate_llm_output(raw_llm, valid_actions)
        except Exception as _ai_exc:
            _msg = str(_ai_exc)
            if "429" in _msg or "quota" in _msg.lower():
                _err = "quota_exceeded"
            elif "api_key" in _msg.lower() or "api key" in _msg.lower() or "invalid" in _msg.lower():
                _err = "invalid_api_key"
            else:
                _err = "ai_unavailable"
            suggestions = {
                "error": _err,
                "least_privilege_policy": None,
                "changes": [],
            }

        try:
            from app.graph.neo4j_repository import GraphRepository
            GraphRepository().store_graph(str(analysis_id), graph)
        except Exception:
            logger.warning("Neo4j unavailable — graph not persisted for analysis %s", analysis_id)

        findings_json_str = json.dumps([f.model_dump() for f in findings])
        repo.update_results(
            analysis_id,
            risk_score=risk_score,
            severity=severity.value,
            findings_json=findings_json_str,
            suggestions_json=json.dumps(suggestions),
            graph_data_json=json.dumps(graph.to_dict()),
            policy_json=real_policy_json,
        )
        db_session.commit()

        # Fire webhooks async — analysis.complete always; privesc.detected if paths found
        try:
            from app.db.models import Webhook
            from app.worker.webhook_delivery import deliver_webhook
            from app.analysis.privesc import PrivescDetector

            hooks = db_session.query(Webhook).filter(Webhook.is_active.is_(True)).all()
            if hooks:
                base_payload = {
                    "analysis_id": analysis_id,
                    "risk_score": round(risk_score, 2),
                    "severity": severity.value,
                }

                privesc_paths = PrivescDetector(graph).detect()

                for hook in hooks:
                    deliver_webhook.delay(hook.id, "analysis.complete", base_payload)
                    if privesc_paths:
                        deliver_webhook.delay(hook.id, "privesc.detected", {
                            **base_payload,
                            "paths_found": len(privesc_paths),
                        })
        except Exception:
            logger.warning("Webhook dispatch failed for analysis %s", analysis_id)

    except Exception:
        db_session.rollback()
        repo.update_status(analysis_id, "failed")
        db_session.commit()
        logger.exception("Analysis task failed for analysis_id=%s", analysis_id)
    finally:
        if owns_session:
            db_session.close()


@celery.task(bind=True)
def analyze_policy_task(
    self,
    analysis_id: int,
    mode: str,
    policy_data: dict | None,
    role_arn: str | None,
    cloud: str = "aws",
) -> None:
    run_analysis(analysis_id, mode, policy_data, role_arn, cloud=cloud)


def _do_rescan(db_session) -> dict:
    """Re-analyze all completed json-mode analyses. Returns scanned/skipped counts."""
    import json as _json
    from sqlalchemy import select
    from app.db.models import Analysis

    rows = list(db_session.scalars(
        select(Analysis).where(Analysis.status == "completed")
    ))
    scanned = 0
    skipped = 0
    for a in rows:
        try:
            policy = _json.loads(a.policy_json)
        except Exception:
            skipped += 1
            continue
        if "Statement" not in policy:
            skipped += 1
            continue
        try:
            run_analysis(a.id, "json", policy, None, db_session=db_session)
            scanned += 1
        except Exception:
            logger.exception("Rescan failed for analysis_id=%s", a.id)
            skipped += 1
    return {"scanned": scanned, "skipped": skipped}


@celery.task
def rescan_completed_analyses() -> dict:
    """Weekly Celery beat task: re-analyze all completed json-mode analyses."""
    from app.db.database import _get_session_factory
    session = _get_session_factory()()
    try:
        result = _do_rescan(session)
        session.commit()
        return result
    except Exception:
        session.rollback()
        logger.exception("rescan_completed_analyses failed")
        return {"scanned": 0, "skipped": 0}
    finally:
        session.close()
