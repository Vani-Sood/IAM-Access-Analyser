"""Unit tests for AuditLog model and AuditLogger service — Batch 21."""
from __future__ import annotations

import hashlib
import json

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import AuditLog, Base


@pytest.fixture(scope="module")
def audit_engine():
    """Isolated in-memory engine so chain tests don't see entries from other tests."""
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)


@pytest.fixture()
def session(audit_engine):
    with Session(audit_engine) as s:
        yield s
        s.rollback()


def _make_logger(session: Session):
    from app.analysis.audit import AuditLogger
    return AuditLogger(session)


# ── Model ─────────────────────────────────────────────────────────────────────


def test_audit_log_model_exists():
    assert AuditLog is not None


def test_audit_log_has_required_columns():
    for col in ("id", "event_type", "actor_id", "actor_email",
                "payload_json", "timestamp", "prev_hash", "entry_hash"):
        assert hasattr(AuditLog, col), f"missing column: {col}"


# ── AuditLogger construction ──────────────────────────────────────────────────


def test_audit_logger_instantiates(session):
    logger = _make_logger(session)
    assert logger is not None


# ── log() ─────────────────────────────────────────────────────────────────────


def test_log_creates_entry(session):
    logger = _make_logger(session)
    entry = logger.log("test.event", {"k": "v"})
    assert entry.id is not None


def test_log_stores_event_type(session):
    logger = _make_logger(session)
    entry = logger.log("auth.login", {})
    assert entry.event_type == "auth.login"


def test_log_stores_payload(session):
    logger = _make_logger(session)
    entry = logger.log("auth.login", {"email": "a@b.com"})
    assert json.loads(entry.payload_json)["email"] == "a@b.com"


def test_log_stores_actor_id(session):
    logger = _make_logger(session)
    entry = logger.log("auth.login", {}, actor_id=42, actor_email="x@y.com")
    assert entry.actor_id == 42
    assert entry.actor_email == "x@y.com"


def test_log_timestamp_set(session):
    logger = _make_logger(session)
    entry = logger.log("ev", {})
    assert entry.timestamp is not None


def test_log_entry_hash_not_empty(session):
    logger = _make_logger(session)
    entry = logger.log("ev", {})
    assert entry.entry_hash and len(entry.entry_hash) == 64


def test_log_prev_hash_not_empty(session):
    logger = _make_logger(session)
    entry = logger.log("ev", {})
    assert entry.prev_hash and len(entry.prev_hash) == 64


# ── Hash chain ────────────────────────────────────────────────────────────────


def test_first_entry_uses_genesis_hash(audit_engine):
    """Uses fresh session so it's the first entry in an empty table."""
    with Session(audit_engine) as s:
        from app.analysis.audit import AuditLogger
        logger = AuditLogger(s)
        # Clear table first for isolation
        s.query(AuditLog).delete()
        s.flush()
        entry = logger.log("genesis.test", {})
        s.flush()
        assert entry.prev_hash == AuditLogger.GENESIS_HASH


def test_second_entry_prev_hash_equals_first_entry_hash(audit_engine):
    with Session(audit_engine) as s:
        from app.analysis.audit import AuditLogger
        logger = AuditLogger(s)
        s.query(AuditLog).delete()
        s.flush()
        first = logger.log("chain.a", {})
        s.flush()
        second = logger.log("chain.b", {})
        s.flush()
        assert second.prev_hash == first.entry_hash


def test_entry_hash_is_deterministic(session):
    from app.analysis.audit import AuditLogger, _ts_str
    logger = _make_logger(session)
    entry = logger.log("det.test", {"x": 1})
    ts = _ts_str(entry.timestamp)
    expected = hashlib.sha256(
        f"{entry.prev_hash}:{ts}:{entry.event_type}:{entry.payload_json}".encode()
    ).hexdigest()
    assert entry.entry_hash == expected


# ── verify_chain() ────────────────────────────────────────────────────────────


def test_verify_chain_valid(audit_engine):
    with Session(audit_engine) as s:
        from app.analysis.audit import AuditLogger
        logger = AuditLogger(s)
        s.query(AuditLog).delete()
        s.flush()
        logger.log("ev.1", {"a": 1})
        s.flush()
        logger.log("ev.2", {"b": 2})
        s.flush()
        logger.log("ev.3", {"c": 3})
        s.flush()
        is_valid, _ = logger.verify_chain()
        assert is_valid is True


def test_verify_chain_detects_tampering(audit_engine):
    with Session(audit_engine) as s:
        from app.analysis.audit import AuditLogger
        logger = AuditLogger(s)
        s.query(AuditLog).delete()
        s.flush()
        logger.log("tamper.a", {})
        s.flush()
        entry = logger.log("tamper.b", {})
        s.flush()
        # Tamper: change payload without recomputing hash
        entry.payload_json = '{"evil": true}'
        s.flush()
        is_valid, tampered_id = logger.verify_chain()
        assert is_valid is False
        assert tampered_id == entry.id


def test_verify_chain_empty_is_valid(audit_engine):
    with Session(audit_engine) as s:
        from app.analysis.audit import AuditLogger
        logger = AuditLogger(s)
        s.query(AuditLog).delete()
        s.flush()
        is_valid, _ = logger.verify_chain()
        assert is_valid is True


# ── export_signed() ───────────────────────────────────────────────────────────


def test_export_signed_returns_dict(audit_engine):
    with Session(audit_engine) as s:
        from app.analysis.audit import AuditLogger
        logger = AuditLogger(s)
        s.query(AuditLog).delete()
        s.flush()
        logger.log("export.test", {})
        s.flush()
        result = logger.export_signed("secret")
        assert isinstance(result, dict)


def test_export_signed_has_required_fields(audit_engine):
    with Session(audit_engine) as s:
        from app.analysis.audit import AuditLogger
        logger = AuditLogger(s)
        s.query(AuditLog).delete()
        s.flush()
        logger.log("export.test", {})
        s.flush()
        result = logger.export_signed("secret")
        for key in ("exported_at", "entries", "chain_valid", "signature"):
            assert key in result, f"missing key: {key}"


def test_export_signed_chain_valid_true(audit_engine):
    with Session(audit_engine) as s:
        from app.analysis.audit import AuditLogger
        logger = AuditLogger(s)
        s.query(AuditLog).delete()
        s.flush()
        logger.log("v1", {})
        logger.log("v2", {})
        s.flush()
        result = logger.export_signed("secret")
        assert result["chain_valid"] is True


def test_export_signed_signature_is_hex_string(audit_engine):
    with Session(audit_engine) as s:
        from app.analysis.audit import AuditLogger
        logger = AuditLogger(s)
        s.query(AuditLog).delete()
        s.flush()
        logger.log("sig.test", {})
        s.flush()
        result = logger.export_signed("my-secret")
        sig = result["signature"]
        assert isinstance(sig, str)
        assert len(sig) == 64
        int(sig, 16)  # must be valid hex


def test_export_signed_signature_changes_with_secret(audit_engine):
    with Session(audit_engine) as s:
        from app.analysis.audit import AuditLogger
        logger = AuditLogger(s)
        s.query(AuditLog).delete()
        s.flush()
        logger.log("sig.change", {})
        s.flush()
        r1 = logger.export_signed("secret-a")
        r2 = logger.export_signed("secret-b")
        assert r1["signature"] != r2["signature"]


def test_export_entries_contain_event_fields(audit_engine):
    with Session(audit_engine) as s:
        from app.analysis.audit import AuditLogger
        logger = AuditLogger(s)
        s.query(AuditLog).delete()
        s.flush()
        logger.log("field.check", {"x": 99}, actor_id=1, actor_email="a@b.com")
        s.flush()
        result = logger.export_signed("s")
        entry = result["entries"][0]
        for key in ("id", "event_type", "actor_id", "actor_email", "payload", "timestamp", "entry_hash"):
            assert key in entry, f"missing key: {key}"
