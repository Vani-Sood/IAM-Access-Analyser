"""Organization and membership management endpoints — Batch 20."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.v1.deps import get_current_user, require_admin
from app.db.database import get_db
from app.db.models import User
from app.db.org_repository import OrgRepository

router = APIRouter(prefix="/api/v1/orgs", tags=["orgs"])

_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_VALID_ROLES = {"creator", "manager", "member"}


# ── Request / Response schemas ────────────────────────────────────────────────


class CreateOrgRequest(BaseModel):
    name: str
    slug: str

    @field_validator("name")
    @classmethod
    def name_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("name must not be blank")
        return v.strip()

    @field_validator("slug")
    @classmethod
    def slug_valid(cls, v: str) -> str:
        if not _SLUG_RE.fullmatch(v):
            raise ValueError(
                "slug must be lowercase alphanumeric with optional hyphens (e.g. 'my-org')"
            )
        return v


class OrgResponse(BaseModel):
    id: int
    name: str
    slug: str


class OrgListResponse(BaseModel):
    items: list[OrgResponse]


class MemberEntry(BaseModel):
    id: int
    email: str
    role: str


class MembersResponse(BaseModel):
    members: list[MemberEntry]


class AddMemberRequest(BaseModel):
    email: str
    role: str = "member"

    @field_validator("role")
    @classmethod
    def role_valid(cls, v: str) -> str:
        if v not in _VALID_ROLES:
            raise ValueError(f"role must be one of {_VALID_ROLES}")
        return v


class ChangeRoleRequest(BaseModel):
    role: str

    @field_validator("role")
    @classmethod
    def role_valid(cls, v: str) -> str:
        if v not in _VALID_ROLES:
            raise ValueError(f"role must be one of {_VALID_ROLES}")
        return v


# ── Helpers ───────────────────────────────────────────────────────────────────


def _require_org_member(db: Session, slug: str, user: User, min_role: str = "member"):
    repo = OrgRepository(db)
    org = repo.get_by_slug(slug)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    membership = repo.get_membership(org_id=org.id, user_id=user.id)
    if membership is None:
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    _check_role(membership.role, min_role)
    return org, membership, repo


_ROLE_RANK = {"creator": 3, "manager": 2, "member": 1}


def _check_role(actual: str, required: str) -> None:
    if _ROLE_RANK.get(actual, 0) < _ROLE_RANK.get(required, 0):
        raise HTTPException(status_code=403, detail=f"Requires role: {required}")


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", status_code=200)
def create_org(
    req: CreateOrgRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> OrgResponse:
    repo = OrgRepository(db)
    try:
        org = repo.create_org(name=req.name, slug=req.slug)
        repo.add_member(org_id=org.id, user_id=current_user.id, role="creator")
        db.commit()
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Organization slug already taken")
    try:
        from app.analysis.audit import AuditLogger
        AuditLogger(db).log(
            "org.create", {"org_id": org.id, "slug": org.slug},
            actor_id=current_user.id, actor_email=current_user.email,
        )
        db.commit()
    except Exception:
        pass
    return OrgResponse(id=org.id, name=org.name, slug=org.slug)


@router.get("", response_model=OrgListResponse)
def list_orgs(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> OrgListResponse:
    repo = OrgRepository(db)
    orgs = repo.list_for_user(user_id=current_user.id)
    return OrgListResponse(
        items=[OrgResponse(id=o.id, name=o.name, slug=o.slug) for o in orgs]
    )


@router.get("/{slug}", response_model=OrgResponse)
def get_org(
    slug: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> OrgResponse:
    org, _, _ = _require_org_member(db, slug, current_user, min_role="member")
    return OrgResponse(id=org.id, name=org.name, slug=org.slug)


@router.get("/{slug}/members", response_model=MembersResponse)
def list_members(
    slug: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MembersResponse:
    org, _, repo = _require_org_member(db, slug, current_user, min_role="member")
    rows = repo.list_members(org.id)
    return MembersResponse(members=[MemberEntry(**r) for r in rows])


@router.post("/{slug}/members", status_code=200)
def add_member(
    slug: str,
    req: AddMemberRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MemberEntry:
    org, actor_m, repo = _require_org_member(db, slug, current_user, min_role="manager")

    # managers can only add as "member"; only creator can assign "manager"
    if actor_m.role == "manager" and req.role != "member":
        raise HTTPException(status_code=403, detail="Managers can only add members")

    target = db.query(User).filter(User.email == req.email).first()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")

    existing = repo.get_membership(org_id=org.id, user_id=target.id)
    if existing is not None:
        raise HTTPException(status_code=409, detail="User is already a member")

    try:
        m = repo.add_member(org_id=org.id, user_id=target.id, role=req.role)
        db.commit()
    except IntegrityError:
        raise HTTPException(status_code=409, detail="User is already a member")
    try:
        from app.analysis.audit import AuditLogger
        AuditLogger(db).log(
            "org.member_add",
            {"org_id": org.id, "slug": slug, "target_user_id": target.id, "role": req.role},
            actor_id=current_user.id, actor_email=current_user.email,
        )
        db.commit()
    except Exception:
        pass
    return MemberEntry(id=target.id, email=target.email, role=m.role)


@router.delete("/{slug}/members/{user_id}", status_code=200)
def remove_member(
    slug: str,
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    org, _, repo = _require_org_member(db, slug, current_user, min_role="manager")

    target_m = repo.get_membership(org_id=org.id, user_id=user_id)
    if target_m is None:
        raise HTTPException(status_code=404, detail="Member not found in organization")

    creator_id = repo.get_creator_user_id(org.id)

    # Creator cannot be removed by anyone
    if target_m.user_id == creator_id:
        raise HTTPException(status_code=403, detail="Cannot remove the organization creator")

    # Manager cannot remove another manager or creator — only creator can
    actor_m = repo.get_membership(org_id=org.id, user_id=current_user.id)
    if _ROLE_RANK.get(actor_m.role, 0) <= _ROLE_RANK.get(target_m.role, 0):
        raise HTTPException(status_code=403, detail="Cannot remove a member with equal or higher role")

    # Prevent removing last creator
    if target_m.role == "creator" and repo.count_owners(org.id) <= 1:
        raise HTTPException(status_code=409, detail="Cannot remove the last creator")

    repo.remove_member(org_id=org.id, user_id=user_id)
    db.commit()
    try:
        from app.analysis.audit import AuditLogger
        AuditLogger(db).log(
            "org.member_remove",
            {"org_id": org.id, "slug": slug, "removed_user_id": user_id},
            actor_id=current_user.id, actor_email=current_user.email,
        )
        db.commit()
    except Exception:
        pass
    return {"removed": user_id}


@router.patch("/{slug}/members/{user_id}/role", status_code=200)
def change_member_role(
    slug: str,
    user_id: int,
    req: ChangeRoleRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MemberEntry:
    org, _, repo = _require_org_member(db, slug, current_user, min_role="creator")

    target_m = repo.get_membership(org_id=org.id, user_id=user_id)
    if target_m is None:
        raise HTTPException(status_code=404, detail="Member not found in organization")

    creator_id = repo.get_creator_user_id(org.id)

    # Creator cannot be demoted by anyone
    if target_m.user_id == creator_id and req.role != "creator":
        raise HTTPException(status_code=403, detail="Cannot demote the organization creator")

    # Only creator can change roles — enforced by min_role="creator" above
    actor_m = repo.get_membership(org_id=org.id, user_id=current_user.id)
    if _ROLE_RANK.get(actor_m.role, 0) <= _ROLE_RANK.get(target_m.role, 0) and target_m.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Cannot change role of a member with equal or higher role")

    # Prevent demoting last creator
    if target_m.role == "creator" and req.role != "creator" and repo.count_owners(org.id) <= 1:
        raise HTTPException(status_code=409, detail="Cannot demote the last creator")

    m = repo.change_role(org_id=org.id, user_id=user_id, role=req.role)
    db.commit()
    try:
        from app.analysis.audit import AuditLogger
        AuditLogger(db).log(
            "org.member_role_change",
            {"org_id": org.id, "slug": slug, "target_user_id": user_id, "new_role": req.role},
            actor_id=current_user.id, actor_email=current_user.email,
        )
        db.commit()
    except Exception:
        pass
    target_user = db.get(User, user_id)
    return MemberEntry(id=user_id, email=target_user.email if target_user else "", role=m.role)
