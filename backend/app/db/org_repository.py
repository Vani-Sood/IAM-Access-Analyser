"""Repository for Organization and Membership persistence."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models import Membership, Organization, User

_VALID_ROLES = {"owner", "admin", "member"}


class OrgRepository:
    def __init__(self, session: Session) -> None:
        self._db = session

    # ── Organizations ─────────────────────────────────────────────────────────

    def create_org(self, *, name: str, slug: str) -> Organization:
        org = Organization(name=name, slug=slug)
        self._db.add(org)
        try:
            self._db.flush()
        except IntegrityError:
            self._db.rollback()
            raise
        self._db.refresh(org)
        return org

    def get_by_slug(self, slug: str) -> Organization | None:
        return self._db.scalar(
            select(Organization).where(Organization.slug == slug)
        )

    def get_by_id(self, org_id: int) -> Organization | None:
        return self._db.get(Organization, org_id)

    def list_for_user(self, user_id: int) -> list[Organization]:
        stmt = (
            select(Organization)
            .join(Membership, Membership.org_id == Organization.id)
            .where(Membership.user_id == user_id)
            .order_by(Organization.id)
        )
        return list(self._db.scalars(stmt))

    # ── Memberships ───────────────────────────────────────────────────────────

    def get_membership(self, *, org_id: int, user_id: int) -> Membership | None:
        return self._db.scalar(
            select(Membership).where(
                Membership.org_id == org_id,
                Membership.user_id == user_id,
            )
        )

    def list_members(self, org_id: int) -> list[dict]:
        stmt = (
            select(User.id, User.email, Membership.role)
            .join(Membership, Membership.user_id == User.id)
            .where(Membership.org_id == org_id)
            .order_by(Membership.id)
        )
        rows = self._db.execute(stmt).all()
        return [{"id": r[0], "email": r[1], "role": r[2]} for r in rows]

    def add_member(self, *, org_id: int, user_id: int, role: str = "member") -> Membership:
        if role not in _VALID_ROLES:
            raise ValueError(f"Invalid role: {role!r}")
        m = Membership(org_id=org_id, user_id=user_id, role=role)
        self._db.add(m)
        try:
            self._db.flush()
        except IntegrityError:
            self._db.rollback()
            raise
        self._db.refresh(m)
        return m

    def remove_member(self, *, org_id: int, user_id: int) -> bool:
        m = self.get_membership(org_id=org_id, user_id=user_id)
        if m is None:
            return False
        self._db.delete(m)
        self._db.flush()
        return True

    def change_role(self, *, org_id: int, user_id: int, role: str) -> Membership | None:
        if role not in _VALID_ROLES:
            raise ValueError(f"Invalid role: {role!r}")
        m = self.get_membership(org_id=org_id, user_id=user_id)
        if m is None:
            return None
        m.role = role
        self._db.flush()
        return m

    def count_owners(self, org_id: int) -> int:
        stmt = select(Membership).where(
            Membership.org_id == org_id,
            Membership.role == "creator",
        )
        return len(list(self._db.scalars(stmt)))

    def get_creator_user_id(self, org_id: int) -> int | None:
        """Return user_id of the original org creator (lowest membership id)."""
        stmt = (
            select(Membership.user_id)
            .where(Membership.org_id == org_id)
            .order_by(Membership.id.asc())
            .limit(1)
        )
        return self._db.scalar(stmt)
