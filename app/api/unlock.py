from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import current_principal
from app.core.pagination import Page, page_result
from app.core.security import Principal
from app.database import get_connection, transaction
from app.repositories.unlock import UnlockRequestRepository
from app.schemas.identity import UnlockDecision, UnlockRequestCreate
from app.services.unlock import UnlockRequestService

router = APIRouter(prefix="/api/unlock-requests", tags=["账号解锁审批"])


@router.post("", status_code=201)
def create_request(data: UnlockRequestCreate, principal: Principal = Depends(current_principal)) -> dict:
    with transaction(immediate=True) as connection:
        return UnlockRequestService(connection).create_request(
            principal,
            target_username=data.target_username,
            reason=data.reason,
            valid_minutes=data.valid_minutes,
            session_scope=data.session_scope,
        )


@router.get("")
def list_requests(
    status: str | None = None,
    target_user_id: int | None = None,
    applicant_user_id: int | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("unlock.read")
    with transaction(immediate=True) as connection:
        UnlockRequestService(connection).expire_due()
    pagination = Page(page, size)
    repository = UnlockRequestRepository(get_connection())
    rows = repository.list(
        status=status,
        target_user_id=target_user_id,
        applicant_user_id=applicant_user_id,
        limit=size,
        offset=pagination.offset,
    )
    conditions: list[str] = []
    params: list = []
    for column, value in (("status", status), ("target_user_id", target_user_id), ("applicant_user_id", applicant_user_id)):
        if value is not None:
            conditions.append(f"{column}=?")
            params.append(value)
    total = repository.count(" AND ".join(conditions), tuple(params))
    return page_result(total=total, page=pagination, rows=rows)


@router.get("/{request_id}")
def get_request(request_id: int, principal: Principal = Depends(current_principal)) -> dict:
    with transaction(immediate=True) as connection:
        return UnlockRequestService(connection).get_detail(principal, request_id)


@router.post("/{request_id}/approvals")
def decide(request_id: int, data: UnlockDecision, principal: Principal = Depends(current_principal)) -> dict:
    with transaction(immediate=True) as connection:
        UnlockRequestService(connection).expire_due()
    with transaction(immediate=True) as connection:
        return UnlockRequestService(connection).decide(principal, request_id, decision=data.decision, note=data.note)


@router.post("/{request_id}/withdraw")
def withdraw(request_id: int, principal: Principal = Depends(current_principal)) -> dict:
    with transaction(immediate=True) as connection:
        UnlockRequestService(connection).expire_due()
    with transaction(immediate=True) as connection:
        return UnlockRequestService(connection).withdraw(principal, request_id)
