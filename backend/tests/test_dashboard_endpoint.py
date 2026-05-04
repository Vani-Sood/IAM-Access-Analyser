"""API tests for GET /api/v1/dashboard/summary — Batch 22 (TDD RED phase)."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.v1.deps import get_current_user
from app.db.database import get_db
from app.db.models import Analysis, Membership, Organization, User


# ── Helpers ───────────────────────────────────────────────────────────────────

_SIMPLE_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
})


def _make_client(test_engine, acting_user: User):
    def override_db():
        with Session(test_engine) as s:
            yield s

    with patch("app.db.database.init_db"):
        from app.main import app
        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides[get_current_user] = lambda: acting_user
        client = TestClient(app, raise_server_exceptions=True)
        yield client
        app.dependency_overrides.clear()


def _insert_user(engine, uid: int, email: str) -> User:
    with Session(engine) as s:
        u = User(id=uid, email=email, hashed_password="hashed", is_active=True)
        s.merge(u)
        s.commit()
    return User(id=uid, email=email, hashed_password="hashed", is_active=True)


def _delete_users(engine, *uids: int) -> None:
    with Session(engine) as s:
        for uid in uids:
            u = s.get(User, uid)
            if u:
                s.delete(u)
        s.commit()


def _create_analysis(engine, org_id=None, risk_score=55.0, severity="medium") -> Analysis:
    with Session(engine) as s:
        a = Analysis(
            policy_hash="hash_" + str(id(object())),
            policy_json=_SIMPLE_POLICY,
            risk_score=risk_score,
            severity=severity,
            findings_json="[]",
            suggestions_json="{}",
            graph_data_json='{"nodes":[],"edges":[]}',
            status="completed",
            org_id=org_id,
        )
        s.add(a)
        s.commit()
        s.refresh(a)
    return a


def _create_org(engine, name: str, slug: str, owner_id: int) -> Organization:
    with Session(engine) as s:
        org = Organization(name=name, slug=slug)
        s.add(org)
        s.flush()
        m = Membership(org_id=org.id, user_id=owner_id, role="owner")
        s.add(m)
        s.commit()
        s.refresh(org)
    return org


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def dash_engine():
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool
    from app.db.models import Base
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)


# ── Tests: authentication ─────────────────────────────────────────────────────

def test_summary_requires_auth(dash_engine):
    with patch("app.db.database.init_db"):
        from app.main import app

        def override_db():
            with Session(dash_engine) as s:
                yield s

        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides.pop(get_current_user, None)
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/v1/dashboard/summary")
            assert resp.status_code == 401
        finally:
            app.dependency_overrides.clear()


# ── Tests: personal (no org) ──────────────────────────────────────────────────

def test_summary_personal_empty(dash_engine):
    user = _insert_user(dash_engine, 700, "dash_empty@test.com")
    for client in _make_client(dash_engine, user):
        resp = client.get("/api/v1/dashboard/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_analyses"] == 0
        assert data["avg_risk_score"] == 0.0
    _delete_users(dash_engine, 700)


def test_summary_personal_counts_analyses(dash_engine):
    user = _insert_user(dash_engine, 701, "dash_count@test.com")
    _create_analysis(dash_engine, org_id=None, risk_score=60.0)
    _create_analysis(dash_engine, org_id=None, risk_score=80.0)
    for client in _make_client(dash_engine, user):
        resp = client.get("/api/v1/dashboard/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_analyses"] >= 2
    _delete_users(dash_engine, 701)


def test_summary_response_has_required_keys(dash_engine):
    user = _insert_user(dash_engine, 702, "dash_keys@test.com")
    for client in _make_client(dash_engine, user):
        resp = client.get("/api/v1/dashboard/summary")
        assert resp.status_code == 200
        data = resp.json()
        for key in ("org_slug", "total_analyses", "avg_risk_score",
                    "severity_distribution", "trend", "heatmap"):
            assert key in data, f"missing key: {key}"
    _delete_users(dash_engine, 702)


def test_summary_severity_distribution_has_all_keys(dash_engine):
    user = _insert_user(dash_engine, 703, "dash_sev@test.com")
    for client in _make_client(dash_engine, user):
        resp = client.get("/api/v1/dashboard/summary")
        dist = resp.json()["severity_distribution"]
        for key in ("critical", "high", "medium", "low", "info"):
            assert key in dist
    _delete_users(dash_engine, 703)


def test_summary_trend_is_list(dash_engine):
    user = _insert_user(dash_engine, 704, "dash_trend@test.com")
    for client in _make_client(dash_engine, user):
        resp = client.get("/api/v1/dashboard/summary")
        assert isinstance(resp.json()["trend"], list)
    _delete_users(dash_engine, 704)


def test_summary_heatmap_is_list(dash_engine):
    user = _insert_user(dash_engine, 705, "dash_heatmap@test.com")
    for client in _make_client(dash_engine, user):
        resp = client.get("/api/v1/dashboard/summary")
        assert isinstance(resp.json()["heatmap"], list)
    _delete_users(dash_engine, 705)


def test_summary_trend_item_shape(dash_engine):
    user = _insert_user(dash_engine, 706, "dash_trend2@test.com")
    _create_analysis(dash_engine, org_id=None)
    for client in _make_client(dash_engine, user):
        resp = client.get("/api/v1/dashboard/summary")
        trend = resp.json()["trend"]
        if trend:
            item = trend[0]
            assert "date" in item
            assert "count" in item
            assert "avg_risk" in item
    _delete_users(dash_engine, 706)


def test_summary_heatmap_item_shape(dash_engine):
    user = _insert_user(dash_engine, 707, "dash_heat2@test.com")
    _create_analysis(dash_engine, org_id=None)
    for client in _make_client(dash_engine, user):
        resp = client.get("/api/v1/dashboard/summary")
        heatmap = resp.json()["heatmap"]
        if heatmap:
            item = heatmap[0]
            assert "service" in item
            assert "action" in item
            assert "count" in item
    _delete_users(dash_engine, 707)


def test_summary_personal_org_slug_is_null(dash_engine):
    user = _insert_user(dash_engine, 708, "dash_slug@test.com")
    for client in _make_client(dash_engine, user):
        resp = client.get("/api/v1/dashboard/summary")
        assert resp.json()["org_slug"] is None
    _delete_users(dash_engine, 708)


# ── Tests: org-scoped ─────────────────────────────────────────────────────────

def test_summary_with_org_slug(dash_engine):
    user = _insert_user(dash_engine, 710, "dash_org@test.com")
    org = _create_org(dash_engine, "Dash Org", "dash-org-1", 710)
    _create_analysis(dash_engine, org_id=org.id, risk_score=70.0)
    for client in _make_client(dash_engine, user):
        resp = client.get("/api/v1/dashboard/summary", headers={"X-Org-Slug": "dash-org-1"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["org_slug"] == "dash-org-1"
        assert data["total_analyses"] >= 1
    _delete_users(dash_engine, 710)


def test_summary_invalid_org_slug_returns_404(dash_engine):
    user = _insert_user(dash_engine, 711, "dash_404@test.com")
    for client in _make_client(dash_engine, user):
        resp = client.get("/api/v1/dashboard/summary", headers={"X-Org-Slug": "nonexistent-org"})
        assert resp.status_code == 404
    _delete_users(dash_engine, 711)


def test_summary_non_member_org_returns_403(dash_engine):
    user_owner = _insert_user(dash_engine, 712, "dash_owner@test.com")
    user_stranger = _insert_user(dash_engine, 713, "dash_stranger@test.com")
    _create_org(dash_engine, "Private Org", "private-org-dash", 712)
    for client in _make_client(dash_engine, user_stranger):
        resp = client.get("/api/v1/dashboard/summary", headers={"X-Org-Slug": "private-org-dash"})
        assert resp.status_code == 403
    _delete_users(dash_engine, 712, 713)


def test_summary_org_slug_echoed_in_response(dash_engine):
    user = _insert_user(dash_engine, 714, "dash_echo@test.com")
    _create_org(dash_engine, "Echo Org", "echo-org-dash", 714)
    for client in _make_client(dash_engine, user):
        resp = client.get("/api/v1/dashboard/summary", headers={"X-Org-Slug": "echo-org-dash"})
        assert resp.json()["org_slug"] == "echo-org-dash"
    _delete_users(dash_engine, 714)


def test_summary_org_analyses_isolated_from_personal(dash_engine):
    """Org analyses don't bleed into personal summary."""
    user = _insert_user(dash_engine, 715, "dash_iso@test.com")
    org = _create_org(dash_engine, "Iso Org", "iso-org-dash", 715)
    _create_analysis(dash_engine, org_id=org.id, risk_score=99.0)
    for client in _make_client(dash_engine, user):
        resp = client.get("/api/v1/dashboard/summary")  # no X-Org-Slug
        data = resp.json()
        assert data["org_slug"] is None
        # Personal analyses should not include the org-scoped one
        if data["total_analyses"] > 0:
            assert data["avg_risk_score"] != 99.0 or data["total_analyses"] != 1
    _delete_users(dash_engine, 715)
