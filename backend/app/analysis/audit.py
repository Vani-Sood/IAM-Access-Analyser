"""Append-only audit log with SHA-256 hash chain and HMAC-signed export."""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AuditLog

# Consistent format for hash computation — avoids timezone round-trip issues
# when reading back naive UTC datetimes from SQLite.
_TS_FMT = "%Y-%m-%dT%H:%M:%S.%f"


def _ts_str(dt: datetime) -> str:
    """Serialize datetime to a stable string for hash computation."""
    return dt.strftime(_TS_FMT)


class AuditLogger:
    GENESIS_HASH = "0" * 64

    def __init__(self, session: Session) -> None:
        self._db = session

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _last_hash(self) -> str:
        last = self._db.scalar(
            select(AuditLog).order_by(AuditLog.id.desc()).limit(1)
        )
        return last.entry_hash if last is not None else self.GENESIS_HASH

    @staticmethod
    def _compute_hash(prev_hash: str, timestamp: str, event_type: str, payload_json: str) -> str:
        data = f"{prev_hash}:{timestamp}:{event_type}:{payload_json}"
        return hashlib.sha256(data.encode()).hexdigest()

    # ── Public API ────────────────────────────────────────────────────────────

    def log(
        self,
        event_type: str,
        payload: dict,
        *,
        actor_id: int | None = None,
        actor_email: str | None = None,
    ) -> AuditLog:
        now = datetime.now(timezone.utc)
        ts = _ts_str(now)
        payload_json = json.dumps(payload, sort_keys=True)
        prev_hash = self._last_hash()
        entry_hash = self._compute_hash(prev_hash, ts, event_type, payload_json)

        entry = AuditLog(
            event_type=event_type,
            actor_id=actor_id,
            actor_email=actor_email,
            payload_json=payload_json,
            timestamp=now,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self._db.add(entry)
        self._db.flush()
        return entry

    def verify_chain(self) -> tuple[bool, int | None]:
        """Return (is_valid, first_tampered_id). None means chain is clean."""
        entries = list(
            self._db.scalars(select(AuditLog).order_by(AuditLog.id))
        )
        prev_hash = self.GENESIS_HASH
        for entry in entries:
            if entry.prev_hash != prev_hash:
                return False, entry.id
            expected = self._compute_hash(
                entry.prev_hash,
                _ts_str(entry.timestamp),
                entry.event_type,
                entry.payload_json,
            )
            if entry.entry_hash != expected:
                return False, entry.id
            prev_hash = entry.entry_hash
        return True, None

    def export_signed(self, secret: str) -> dict:
        entries = list(
            self._db.scalars(select(AuditLog).order_by(AuditLog.id))
        )
        is_valid, _ = self.verify_chain()

        serialized = [
            {
                "id": e.id,
                "event_type": e.event_type,
                "actor_id": e.actor_id,
                "actor_email": e.actor_email,
                "payload": json.loads(e.payload_json),
                "timestamp": e.timestamp.isoformat(),
                "prev_hash": e.prev_hash,
                "entry_hash": e.entry_hash,
            }
            for e in entries
        ]

        body = json.dumps(serialized, sort_keys=True)
        signature = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()

        return {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "entries": serialized,
            "chain_valid": is_valid,
            "signature": signature,
        }

    def list_entries(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        event_type: str | None = None,
    ) -> tuple[list[AuditLog], int]:
        stmt = select(AuditLog).order_by(AuditLog.id.desc())
        count_stmt = select(AuditLog)
        if event_type:
            stmt = stmt.where(AuditLog.event_type == event_type)
            count_stmt = count_stmt.where(AuditLog.event_type == event_type)

        from sqlalchemy import func, select as _select
        total = self._db.scalar(
            _select(func.count()).select_from(count_stmt.subquery())
        ) or 0
        items = list(self._db.scalars(stmt.limit(limit).offset(offset)))
        return items, total
