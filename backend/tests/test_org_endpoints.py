"""Tests for org management endpoints — Batch 20 (TDD RED phase).

Tests cover: create org, list orgs, get org, list members, add/remove/change-role.
RBAC enforcement: owner > admin > member > stranger.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.v1.deps import get_current_user
from app.db.database import get_db
from app.db.models import Membership, Organization, User


# ── Shared helpers ────────────────────────────────────────────────────────────

def _make_client(test_engine, acting_user: User) -> TestClient:
    """Return a TestClient with get_current_user overridden to acting_user."""
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


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def users(test_engine):
    """Four users with IDs 500-503; cleaned up after test."""
    owner = _insert_user(test_engine, 500, "owner@org.test")
    admin = _insert_user(test_engine, 501, "admin@org.test")
    member = _insert_user(test_engine, 502, "member@org.test")
    stranger = _insert_user(test_engine, 503, "stranger@org.test")
    yield {"owner": owner, "admin": admin, "member": member, "stranger": stranger}
    _delete_users(test_engine, 500, 501, 502, 503)


@pytest.fixture()
def org_with_members(test_engine, users):
    """Org 'test-corp' with owner/admin/member preloaded."""
    slug = "test-corp"
    with Session(test_engine) as s:
        org = Organization(name="Test Corp", slug=slug)
        s.add(org)
        s.flush()
        s.add_all([
            Membership(org_id=org.id, user_id=users["owner"].id, role="owner"),
            Membership(org_id=org.id, user_id=users["admin"].id, role="admin"),
            Membership(org_id=org.id, user_id=users["member"].id, role="member"),
        ])
        s.commit()
    yield slug
    _delete_org_by_slug(test_engine, slug)


# ── Auth ─────────────────────────────────────────────────────────────────────


def test_create_org_requires_auth():
    with patch("app.db.database.init_db"):
        from app.main import app
        with TestClient(app) as c:
            resp = c.post("/api/v1/orgs", json={"name": "X", "slug": "x"})
    assert resp.status_code == 401


def test_list_orgs_requires_auth():
    with patch("app.db.database.init_db"):
        from app.main import app
        with TestClient(app) as c:
            resp = c.get("/api/v1/orgs")
    assert resp.status_code == 401


def test_get_org_requires_auth():
    with patch("app.db.database.init_db"):
        from app.main import app
        with TestClient(app) as c:
            resp = c.get("/api/v1/orgs/any-slug")
    assert resp.status_code == 401


# ── Create org ────────────────────────────────────────────────────────────────


def test_create_org_returns_200(test_engine, users):
    slug = "new-corp-create"
    for client in _make_client(test_engine, users["owner"]):
        resp = client.post("/api/v1/orgs", json={"name": "New Corp", "slug": slug})
        assert resp.status_code in (200, 201)
    _delete_org_by_slug(test_engine, slug)


def test_create_org_response_has_fields(test_engine, users):
    slug = "new-corp-fields"
    for client in _make_client(test_engine, users["owner"]):
        data = client.post("/api/v1/orgs", json={"name": "New Corp", "slug": slug}).json()
        assert "id" in data
        assert data["slug"] == slug
        assert data["name"] == "New Corp"
    _delete_org_by_slug(test_engine, slug)


def test_create_org_adds_creator_as_owner(test_engine, users):
    slug = "new-corp-owner"
    for client in _make_client(test_engine, users["owner"]):
        client.post("/api/v1/orgs", json={"name": "New Corp", "slug": slug})
    with Session(test_engine) as s:
        org = s.query(Organization).filter_by(slug=slug).first()
        assert org is not None
        m = s.query(Membership).filter_by(org_id=org.id, user_id=users["owner"].id).first()
        assert m is not None
        assert m.role == "owner"
    _delete_org_by_slug(test_engine, slug)


def test_create_org_duplicate_slug_returns_409(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["owner"]):
        resp = client.post("/api/v1/orgs", json={"name": "Dupe", "slug": org_with_members})
        assert resp.status_code == 409


def test_create_org_missing_name_returns_422(test_engine, users):
    for client in _make_client(test_engine, users["owner"]):
        resp = client.post("/api/v1/orgs", json={"slug": "only-slug"})
        assert resp.status_code == 422


def test_create_org_missing_slug_returns_422(test_engine, users):
    for client in _make_client(test_engine, users["owner"]):
        resp = client.post("/api/v1/orgs", json={"name": "Only Name"})
        assert resp.status_code == 422


def test_create_org_invalid_slug_chars_returns_422(test_engine, users):
    for client in _make_client(test_engine, users["owner"]):
        resp = client.post("/api/v1/orgs", json={"name": "Bad", "slug": "has spaces"})
        assert resp.status_code == 422


# ── List orgs ─────────────────────────────────────────────────────────────────


def test_list_orgs_returns_my_orgs(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["owner"]):
        data = client.get("/api/v1/orgs").json()
        slugs = [o["slug"] for o in data["items"]]
        assert org_with_members in slugs


def test_list_orgs_stranger_not_included(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["stranger"]):
        data = client.get("/api/v1/orgs").json()
        slugs = [o["slug"] for o in data["items"]]
        assert org_with_members not in slugs


def test_list_orgs_has_items_list(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["member"]):
        data = client.get("/api/v1/orgs").json()
        assert "items" in data
        assert isinstance(data["items"], list)


# ── Get org ───────────────────────────────────────────────────────────────────


def test_get_org_member_returns_200(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["member"]):
        resp = client.get(f"/api/v1/orgs/{org_with_members}")
        assert resp.status_code == 200


def test_get_org_has_fields(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["owner"]):
        data = client.get(f"/api/v1/orgs/{org_with_members}").json()
        assert "id" in data
        assert "name" in data
        assert data["slug"] == org_with_members


def test_get_org_stranger_returns_403(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["stranger"]):
        resp = client.get(f"/api/v1/orgs/{org_with_members}")
        assert resp.status_code == 403


def test_get_org_nonexistent_returns_404(test_engine, users):
    for client in _make_client(test_engine, users["owner"]):
        resp = client.get("/api/v1/orgs/definitely-does-not-exist-xyz")
        assert resp.status_code == 404


# ── List members ──────────────────────────────────────────────────────────────


def test_list_members_returns_200_for_member(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["member"]):
        resp = client.get(f"/api/v1/orgs/{org_with_members}/members")
        assert resp.status_code == 200


def test_list_members_contains_all_members(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["owner"]):
        data = client.get(f"/api/v1/orgs/{org_with_members}/members").json()
        emails = [m["email"] for m in data["members"]]
        assert "owner@org.test" in emails
        assert "admin@org.test" in emails
        assert "member@org.test" in emails


def test_list_members_includes_role(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["owner"]):
        data = client.get(f"/api/v1/orgs/{org_with_members}/members").json()
        owner_entry = next(m for m in data["members"] if m["email"] == "owner@org.test")
        assert owner_entry["role"] == "owner"


def test_list_members_stranger_returns_403(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["stranger"]):
        resp = client.get(f"/api/v1/orgs/{org_with_members}/members")
        assert resp.status_code == 403


# ── Add member ────────────────────────────────────────────────────────────────


def test_add_member_by_owner_returns_200(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["owner"]):
        resp = client.post(
            f"/api/v1/orgs/{org_with_members}/members",
            json={"email": users["stranger"].email, "role": "member"},
        )
        assert resp.status_code in (200, 201)
    # cleanup
    with Session(test_engine) as s:
        org = s.query(Organization).filter_by(slug=org_with_members).first()
        if org:
            m = s.query(Membership).filter_by(org_id=org.id, user_id=users["stranger"].id).first()
            if m:
                s.delete(m)
            s.commit()


def test_add_member_by_admin_returns_200(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["admin"]):
        resp = client.post(
            f"/api/v1/orgs/{org_with_members}/members",
            json={"email": users["stranger"].email, "role": "member"},
        )
        assert resp.status_code in (200, 201)
    # cleanup
    with Session(test_engine) as s:
        org = s.query(Organization).filter_by(slug=org_with_members).first()
        if org:
            m = s.query(Membership).filter_by(org_id=org.id, user_id=users["stranger"].id).first()
            if m:
                s.delete(m)
            s.commit()


def test_add_member_by_member_returns_403(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["member"]):
        resp = client.post(
            f"/api/v1/orgs/{org_with_members}/members",
            json={"email": users["stranger"].email, "role": "member"},
        )
        assert resp.status_code == 403


def test_add_existing_member_returns_409(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["owner"]):
        resp = client.post(
            f"/api/v1/orgs/{org_with_members}/members",
            json={"email": users["member"].email, "role": "member"},
        )
        assert resp.status_code == 409


def test_add_nonexistent_user_returns_404(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["owner"]):
        resp = client.post(
            f"/api/v1/orgs/{org_with_members}/members",
            json={"email": "nobody@nowhere.test", "role": "member"},
        )
        assert resp.status_code == 404


def test_add_member_nonmember_returns_403(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["stranger"]):
        resp = client.post(
            f"/api/v1/orgs/{org_with_members}/members",
            json={"email": users["owner"].email, "role": "member"},
        )
        assert resp.status_code == 403


# ── Remove member ─────────────────────────────────────────────────────────────


def test_remove_member_by_owner_returns_200(test_engine, users, org_with_members):
    # First add stranger as member
    with Session(test_engine) as s:
        org = s.query(Organization).filter_by(slug=org_with_members).first()
        s.add(Membership(org_id=org.id, user_id=users["stranger"].id, role="member"))
        s.commit()

    for client in _make_client(test_engine, users["owner"]):
        resp = client.delete(
            f"/api/v1/orgs/{org_with_members}/members/{users['stranger'].id}"
        )
        assert resp.status_code in (200, 204)


def test_remove_member_by_member_returns_403(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["member"]):
        resp = client.delete(
            f"/api/v1/orgs/{org_with_members}/members/{users['admin'].id}"
        )
        assert resp.status_code == 403


def test_remove_last_owner_returns_409(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["owner"]):
        resp = client.delete(
            f"/api/v1/orgs/{org_with_members}/members/{users['owner'].id}"
        )
        assert resp.status_code == 409


def test_remove_nonexistent_member_returns_404(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["owner"]):
        resp = client.delete(
            f"/api/v1/orgs/{org_with_members}/members/{users['stranger'].id}"
        )
        assert resp.status_code == 404


def test_remove_member_stranger_actor_returns_403(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["stranger"]):
        resp = client.delete(
            f"/api/v1/orgs/{org_with_members}/members/{users['member'].id}"
        )
        assert resp.status_code == 403


# ── Change role ───────────────────────────────────────────────────────────────


def test_change_role_by_owner_returns_200(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["owner"]):
        resp = client.patch(
            f"/api/v1/orgs/{org_with_members}/members/{users['member'].id}/role",
            json={"role": "admin"},
        )
        assert resp.status_code == 200
    # Reset back
    with Session(test_engine) as s:
        org = s.query(Organization).filter_by(slug=org_with_members).first()
        m = s.query(Membership).filter_by(org_id=org.id, user_id=users["member"].id).first()
        if m:
            m.role = "member"
        s.commit()


def test_change_role_by_admin_returns_403(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["admin"]):
        resp = client.patch(
            f"/api/v1/orgs/{org_with_members}/members/{users['member'].id}/role",
            json={"role": "admin"},
        )
        assert resp.status_code == 403


def test_change_role_by_member_returns_403(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["member"]):
        resp = client.patch(
            f"/api/v1/orgs/{org_with_members}/members/{users['admin'].id}/role",
            json={"role": "owner"},
        )
        assert resp.status_code == 403


def test_change_role_cannot_demote_last_owner(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["owner"]):
        resp = client.patch(
            f"/api/v1/orgs/{org_with_members}/members/{users['owner'].id}/role",
            json={"role": "admin"},
        )
        assert resp.status_code == 409


def test_change_role_invalid_role_returns_422(test_engine, users, org_with_members):
    for client in _make_client(test_engine, users["owner"]):
        resp = client.patch(
            f"/api/v1/orgs/{org_with_members}/members/{users['member'].id}/role",
            json={"role": "superuser"},
        )
        assert resp.status_code == 422
