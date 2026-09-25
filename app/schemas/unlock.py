from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

SessionScope = Literal["all", "current"]


class UnlockRequestCreate(BaseModel):
    target_username: str = Field(min_length=3, max_length=64)
    reason: str = Field(min_length=5, max_length=500)
    validity_minutes: int = Field(ge=5, le=240)
    session_scope: SessionScope = "all"


class UnlockDecision(BaseModel):
    decision: Literal["approved", "rejected"]
    comment: str = Field(default="", max_length=500)


class UnlockWithdraw(BaseModel):
    reason: str = Field(default="", max_length=500)
