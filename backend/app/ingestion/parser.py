from __future__ import annotations

from enum import Enum
from typing import Optional, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic.alias_generators import to_pascal


class PolicyValidationError(ValueError):
    pass


class Effect(str, Enum):
    ALLOW = "Allow"
    DENY = "Deny"


class Statement(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=to_pascal,
    )

    sid: Optional[str] = None
    effect: Effect
    action: Optional[Union[str, list[str]]] = None
    not_action: Optional[Union[str, list[str]]] = None
    resource: Optional[Union[str, list[str]]] = None
    not_resource: Optional[Union[str, list[str]]] = None
    principal: Optional[Union[str, dict, list]] = None
    not_principal: Optional[Union[str, dict, list]] = None
    condition: Optional[dict] = None

    @model_validator(mode="after")
    def _validate_action_xor_not_action(self) -> Statement:
        has_action = self.action is not None
        has_not_action = self.not_action is not None
        if not has_action and not has_not_action:
            raise PolicyValidationError(
                "Statement must have 'Action' or 'NotAction'"
            )
        if has_action and has_not_action:
            raise PolicyValidationError(
                "Statement cannot have both 'Action' and 'NotAction'"
            )
        return self

    @property
    def actions(self) -> list[str]:
        src = self.action
        if src is None:
            return []
        return [src] if isinstance(src, str) else list(src)

    @property
    def not_actions(self) -> list[str]:
        src = self.not_action
        if src is None:
            return []
        return [src] if isinstance(src, str) else list(src)

    @property
    def resources(self) -> list[str]:
        src = self.resource if self.resource is not None else self.not_resource
        if src is None:
            return []
        return [src] if isinstance(src, str) else list(src)


class PolicyDoc(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=to_pascal,
    )

    version: str = Field(default="2012-10-17")
    statement: list[Statement] = Field(min_length=1)
