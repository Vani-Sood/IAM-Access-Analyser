"""Tests for AnalysisRepository CRUD operations — Batch 10."""
from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from app.db.repository import AnalysisRepository


@pytest.fixture()
def session(test_engine):
    with Session(test_engine) as s:
        yield s
        s.rollback()


@pytest.fixture()
def repo(session):
    return AnalysisRepository(session)


_SAMPLE = dict(
    policy_hash="deadbeef",
    policy_json='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}',
    risk_score=6.5,
    severity="HIGH",
    findings_json='[{"rule_id":"S3_WILDCARD","severity":"HIGH","message":"Wildcard S3 action","statement_idx":0}]',
    suggestions_json='{"least_privilege_policy":null,"changes":[]}',
    graph_data_json='{"nodes":[],"edges":[]}',
)


def test_create_returns_analysis_with_id(repo):
    result = repo.create(**_SAMPLE)
    assert result.id is not None
    assert result.risk_score == 6.5


def test_get_by_id_returns_record(repo):
    created = repo.create(**_SAMPLE)
    fetched = repo.get_by_id(created.id)
    assert fetched is not None
    assert fetched.id == created.id
    assert fetched.severity == "HIGH"


def test_get_by_id_missing_returns_none(repo):
    result = repo.get_by_id(999999)
    assert result is None


def test_list_all_returns_records(repo):
    repo.create(**_SAMPLE)
    repo.create(**{**_SAMPLE, "policy_hash": "anotherHash"})
    results = repo.list_all(limit=50, offset=0)
    assert len(results) >= 2


def test_list_all_respects_limit(repo):
    for i in range(5):
        repo.create(**{**_SAMPLE, "policy_hash": f"hash_{i}"})
    results = repo.list_all(limit=2, offset=0)
    assert len(results) == 2


def test_list_all_respects_offset(repo):
    for i in range(4):
        repo.create(**{**_SAMPLE, "policy_hash": f"off_hash_{i}"})
    page1 = repo.list_all(limit=2, offset=0)
    page2 = repo.list_all(limit=2, offset=2)
    ids_page1 = {r.id for r in page1}
    ids_page2 = {r.id for r in page2}
    assert ids_page1.isdisjoint(ids_page2)


def test_list_all_ordered_newest_first(repo):
    r1 = repo.create(**{**_SAMPLE, "policy_hash": "oldest"})
    r2 = repo.create(**{**_SAMPLE, "policy_hash": "newest"})
    results = repo.list_all(limit=50, offset=0)
    ids = [r.id for r in results]
    assert ids.index(r2.id) < ids.index(r1.id)


def test_count_returns_total(repo):
    before = repo.count()
    repo.create(**{**_SAMPLE, "policy_hash": "count_test"})
    after = repo.count()
    assert after == before + 1
