"""Unit tests for Organization and Membership ORM models — Batch 20."""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import Base, Membership, Organization, User


@pytest.fixture(scope="module")
def engine():
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)


@pytest.fixture()
def session(engine):
    with Session(engine) as s:
        yield s
        s.rollback()


def _make_user(session: Session, uid: int, email: str) -> User:
    u = User(id=uid, email=email, hashed_password="x", is_active=True)
    session.add(u)
    session.flush()
    return u


def _make_org(session: Session, name: str = "Acme", slug: str = "acme") -> Organization:
    o = Organization(name=name, slug=slug)
    session.add(o)
    session.flush()
    return o


# ── Organization ──────────────────────────────────────────────────────────────


def test_org_creation(session):
    org = _make_org(session)
    assert org.id is not None
    assert org.name == "Acme"
    assert org.slug == "acme"


def test_org_has_created_at(session):
    org = _make_org(session, slug="acme2")
    assert org.created_at is not None


def test_org_slug_unique_constraint(session):
    _make_org(session, slug="unique-slug")
    with pytest.raises(IntegrityError):
        _make_org(session, slug="unique-slug")


def test_org_name_not_nullable(session):
    with pytest.raises(Exception):
        o = Organization(slug="no-name")
        session.add(o)
        session.flush()


def test_org_slug_not_nullable(session):
    with pytest.raises(Exception):
        o = Organization(name="No Slug")
        session.add(o)
        session.flush()


# ── Membership ────────────────────────────────────────────────────────────────


def test_membership_creation(session):
    u = _make_user(session, 200, "m@test.com")
    o = _make_org(session, slug="mb-test")
    m = Membership(org_id=o.id, user_id=u.id, role="owner")
    session.add(m)
    session.flush()
    assert m.id is not None
    assert m.role == "owner"


def test_membership_has_created_at(session):
    u = _make_user(session, 201, "m2@test.com")
    o = _make_org(session, slug="mb-test2")
    m = Membership(org_id=o.id, user_id=u.id, role="member")
    session.add(m)
    session.flush()
    assert m.created_at is not None


def test_membership_unique_per_org_user(session):
    u = _make_user(session, 202, "m3@test.com")
    o = _make_org(session, slug="mb-test3")
    session.add(Membership(org_id=o.id, user_id=u.id, role="owner"))
    session.flush()
    with pytest.raises(IntegrityError):
        session.add(Membership(org_id=o.id, user_id=u.id, role="member"))
        session.flush()


def test_membership_default_role_is_member(session):
    u = _make_user(session, 203, "m4@test.com")
    o = _make_org(session, slug="mb-test4")
    m = Membership(org_id=o.id, user_id=u.id)
    session.add(m)
    session.flush()
    assert m.role == "member"


# ── Analysis org_id ───────────────────────────────────────────────────────────


def test_analysis_has_org_id_column():
    from app.db.models import Analysis

    assert hasattr(Analysis, "org_id")


def test_analysis_org_id_nullable():
    from sqlalchemy import inspect

    from app.db.models import Analysis

    col = inspect(Analysis).mapper.columns["org_id"]
    assert col.nullable is True
