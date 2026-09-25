from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import current_principal, current_principal_allow_locked
from app.core.pagination import Page, page_result
from app.core.security import Principal
from app.database import get_connection, transaction
from app.schemas.unlock import UnlockDecision, UnlockRequestCreate, UnlockWithdraw
from app.services.unlock import UnlockService

router = APIRouter(prefix="/api/unlock-requests", tags=["紧急解锁"])


def _sweep() -> None:
    # 在写事务之外收敛过期/审批链失效的申请，维护性终态独立落盘。
    UnlockService(get_connection()).sweep()


@router.post("", status_code=201)
def create_unlock_request(
    data: UnlockRequestCreate,
    principal: Principal = Depends(current_principal_allow_locked),
) -> dict:
    _sweep()
    with transaction(immediate=True) as connection:
        return UnlockService(connection).create_request(principal, data.model_dump())


@router.get("/mine")
def list_my_unlock_requests(
    status: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    principal: Principal = Depends(current_principal_allow_locked),
) -> dict:
    pagination = Page(page, size)
    service = UnlockService(get_connection())
    rows, total = service.list_own(principal, status=status, limit=size, offset=pagination.offset)
    return page_result(total=total, page=pagination, rows=rows)


@router.get("")
def list_unlock_requests(
    status: str | None = None,
    target_user_id: int | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    principal: Principal = Depends(current_principal),
) -> dict:
    pagination = Page(page, size)
    service = UnlockService(get_connection())
    rows, total = service.list_requests(
        principal, status=status, target_user_id=target_user_id, limit=size, offset=pagination.offset
    )
    return page_result(total=total, page=pagination, rows=rows)


@router.get("/{request_id}")
def get_unlock_request(request_id: int, principal: Principal = Depends(current_principal_allow_locked)) -> dict:
    return UnlockService(get_connection()).detail(request_id, principal=principal)


@router.post("/{request_id}/decision")
def decide_unlock_request(
    request_id: int,
    data: UnlockDecision,
    principal: Principal = Depends(current_principal),
) -> dict:
    _sweep()
    with transaction(immediate=True) as connection:
        return UnlockService(connection).decide(principal, request_id, data.decision, data.comment)


@router.post("/{request_id}/withdraw")
def withdraw_unlock_request(
    request_id: int,
    data: UnlockWithdraw,
    principal: Principal = Depends(current_principal_allow_locked),
) -> dict:
    _sweep()
    with transaction(immediate=True) as connection:
        return UnlockService(connection).withdraw(principal, request_id, data.reason)
