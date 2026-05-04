"""Tests for org-scoped analysis access — Batch 20 (TDD RED phase).

Covers:
- X-Org-Slug header sets org_id on new analyses
- GET /analyses filters by org context
- Individual analysis access respects org membership
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.api.v1.deps import get_current_user
from app.db.database import get_db
from app.db.models import Membership, Organization, User

SAFE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::my-bucket/*",
        }
    ],
}

MOCK_LLM = (
    '{"least_privilege_policy": {"Version":"2012-10-17","Statement":[]}, "changes": []}'
)


def _make_sync_delay(engine, mock_llm):
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def _delay(analysis_id, mode, policy_data, role_arn):
        from app.worker.tasks import run_analysis

        db = factory()
        try:
            with patch("app.ai.llm_client.call_llm", return_value=mock_llm):
                run_analysis(analysis_id, mode, policy_data, role_arn, db_session=db)
            db.commit()
        finally:
            db.close()
        m = MagicMock()
        m.id = "test-task-rbac"
        return m

    return _delay


def _insert_user(engine, uid: int, email: str) -> User:
    with Session(engine) as s:
        existing = s.get(User, uid)
        if existing:
            return existing
        u = User(id=uid, email=email, hashed_password="x", is_active=True)
        s.add(u)
        s.commit()
        s.refresh(u)
    return u


def _delete_users(engine, *uids: int) -> None:
    with Session(engine) as s:
        for uid in uids:
            u = s.get(User, uid)
            if u:
                s.delete(u)
        s.commit()


def _delete_org_by_slug(engine, slug: str) -> None:
    with Session(engine) as s:
        org = s.query(Organization).filter_by(slug=slug).first()
        if org:
            s.query(Membership).filter_by(org_id=org.id).delete()
            s.delete(org)
        s.commit()


@pytest.fixture()
def rbac_setup(test_engine):
    """Two users, one org. user A=member, user B=stranger."""
    user_a = _insert_user(test_engine, 600, "rbac_a@test.com")
    user_b = _insert_user(test_engine, 601, "rbac_b@test.com")
    slug = "rbac-org"
    with Session(test_engine) as s:
        org = Organization(name="RBAC Org", slug=slug)
        s.add(org)
        s.flush()
        s.add(Membership(org_id=org.id, user_id=user_a.id, role="owner"))
        s.commit()
        oid = org.id
    yield {"user_a": user_a, "user_b": user_b, "slug": slug, "org_id": oid}
    _delete_org_by_slug(test_engine, slug)
    _delete_users(test_engine, 600, 601)


def _client_for(test_engine, user: User):
    def override_db():
        with Session(test_engine) as s:
            yield s

    with (
        patch("app.db.database.init_db"),
        patch(
            "app.worker.tasks.analyze_policy_task.delay",
            side_effect=_make_sync_delay(test_engine, MOCK_LLM),
        ),
    ):
        from app.main import app

        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides[get_current_user] = lambda: user
        with TestClient(app) as c:
            yield c
        app.dependency_overrides.clear()


# ── Org-scoped analysis creation ──────────────────────────────────────────────


def test_analyze_with_org_header_sets_org_id(test_engine, rbac_setup):
    slug = rbac_setup["slug"]
    user_a = rbac_setup["user_a"]
    for client in _client_for(test_engine, user_a):
        resp = client.post(
            "/api/v1/analyze",
            json={"mode": "json", "policy": SAFE_POLICY},
            headers={"X-Org-Slug": slug},
        )
        assert resp.status_code == 200
        aid = resp.json()["id"]

    # Verify org_id set on analysis
    with Session(test_engine) as s:
        from app.db.models import Analysis

        rec = s.get(Analysis, aid)
        assert rec is not None
        assert rec.org_id == rbac_setup["org_id"]


def test_analyze_without_org_header_has_null_org_id(test_engine, rbac_setup):
    user_a = rbac_setup["user_a"]
    aid = None
    for client in _client_for(test_engine, user_a):
        resp = client.post(
            "/api/v1/analyze",
            json={"mode": "json", "policy": SAFE_POLICY},
        )
        assert resp.status_code == 200
        aid = resp.json()["id"]

    with Session(test_engine) as s:
        from app.db.models import Analysis

        rec = s.get(Analysis, aid)
        assert rec is not None
        assert rec.org_id is None


def test_analyze_with_org_header_nonmember_returns_403(test_engine, rbac_setup):
    slug = rbac_setup["slug"]
    user_b = rbac_setup["user_b"]
    for client in _client_for(test_engine, user_b):
        resp = client.post(
            "/api/v1/analyze",
            json={"mode": "json", "policy": SAFE_POLICY},
            headers={"X-Org-Slug": slug},
        )
        assert resp.status_code == 403


def test_analyze_with_invalid_org_header_returns_404(test_engine, rbac_setup):
    user_a = rbac_setup["user_a"]
    for client in _client_for(test_engine, user_a):
        resp = client.post(
            "/api/v1/analyze",
            json={"mode": "json", "policy": SAFE_POLICY},
            headers={"X-Org-Slug": "no-such-org-xyz"},
        )
        assert resp.status_code == 404


# ── Org-scoped analysis listing ───────────────────────────────────────────────


def test_list_analyses_with_org_header_filters_by_org(test_engine, rbac_setup):
    slug = rbac_setup["slug"]
    user_a = rbac_setup["user_a"]
    org_analysis_id = None

    for client in _client_for(test_engine, user_a):
        # Create one org-scoped analysis
        resp = client.post(
            "/api/v1/analyze",
            json={"mode": "json", "policy": SAFE_POLICY},
            headers={"X-Org-Slug": slug},
        )
        org_analysis_id = resp.json()["id"]

        # Create one personal analysis (no header)
        client.post("/api/v1/analyze", json={"mode": "json", "policy": SAFE_POLICY})

        # List with org header → should only include org analyses
        list_resp = client.get("/api/v1/analyses", headers={"X-Org-Slug": slug})
        assert list_resp.status_code == 200
        ids = [item["id"] for item in list_resp.json()["items"]]
        assert org_analysis_id in ids


def test_list_analyses_with_org_header_excludes_personal(test_engine, rbac_setup):
    slug = rbac_setup["slug"]
    user_a = rbac_setup["user_a"]
    personal_id = None

    for client in _client_for(test_engine, user_a):
        # Create personal analysis
        resp = client.post("/api/v1/analyze", json={"mode": "json", "policy": SAFE_POLICY})
        personal_id = resp.json()["id"]

        # List with org header → personal analysis should NOT appear
        list_resp = client.get("/api/v1/analyses", headers={"X-Org-Slug": slug})
        assert list_resp.status_code == 200
        ids = [item["id"] for item in list_resp.json()["items"]]
        assert personal_id not in ids


def test_list_analyses_with_org_header_nonmember_returns_403(test_engine, rbac_setup):
    slug = rbac_setup["slug"]
    user_b = rbac_setup["user_b"]
    for client in _client_for(test_engine, user_b):
        resp = client.get("/api/v1/analyses", headers={"X-Org-Slug": slug})
        assert resp.status_code == 403


def test_list_analyses_with_invalid_org_header_returns_404(test_engine, rbac_setup):
    user_a = rbac_setup["user_a"]
    for client in _client_for(test_engine, user_a):
        resp = client.get("/api/v1/analyses", headers={"X-Org-Slug": "ghost-org-xyz"})
        assert resp.status_code == 404


# ── Individual analysis access control ────────────────────────────────────────


def test_get_org_analysis_by_member_returns_200(test_engine, rbac_setup):
    slug = rbac_setup["slug"]
    user_a = rbac_setup["user_a"]
    aid = None

    for client in _client_for(test_engine, user_a):
        resp = client.post(
            "/api/v1/analyze",
            json={"mode": "json", "policy": SAFE_POLICY},
            headers={"X-Org-Slug": slug},
        )
        aid = resp.json()["id"]
        get_resp = client.get(f"/api/v1/analyses/{aid}")
        assert get_resp.status_code == 200


def test_get_org_analysis_by_nonmember_returns_403(test_engine, rbac_setup):
    slug = rbac_setup["slug"]
    user_a = rbac_setup["user_a"]
    user_b = rbac_setup["user_b"]
    aid = None

    for client in _client_for(test_engine, user_a):
        resp = client.post(
            "/api/v1/analyze",
            json={"mode": "json", "policy": SAFE_POLICY},
            headers={"X-Org-Slug": slug},
        )
        aid = resp.json()["id"]

    for client in _client_for(test_engine, user_b):
        resp = client.get(f"/api/v1/analyses/{aid}")
        assert resp.status_code == 403
