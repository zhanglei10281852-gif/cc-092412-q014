from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.dependencies import current_principal
from app.core.errors import AuthenticationError
from app.core.security import Principal
from app.database import get_connection, transaction
from app.schemas.identity import LoginRequest, LoginResponse
from app.services.auth import AuthService

router = APIRouter(prefix="/api/auth", tags=["身份认证"])


@router.post("/bootstrap", status_code=201)
def bootstrap(data: LoginRequest) -> dict:
    with transaction(immediate=True) as connection:
        user = AuthService(connection).bootstrap_admin(data.username, data.password, "系统管理员")
        user.pop("password_hash", None)
        return user


@router.post("/login", response_model=LoginResponse)
def login(data: LoginRequest) -> dict:
    with transaction(immediate=True) as connection:
        try:
            token, result = AuthService(connection).login(data.username, data.password, data.client_label)
        except AuthenticationError:
            # 预期内的认证失败同样要保留失败计数、锁定状态与拒绝审计，不能随异常整体回滚。
            connection.commit()
            raise
        public_user = dict(result["user"])
        public_user.pop("password_hash", None)
        return {"token": token, "expires_at": result["expires_at"], "user": public_user, "permissions": result["permissions"]}


@router.get("/me")
def me(principal: Principal = Depends(current_principal)) -> dict:
    return {
        "user_id": principal.user_id,
        "username": principal.username,
        "display_name": principal.display_name,
        "department_id": principal.department_id,
        "permissions": sorted(principal.permissions),
        "session_id": principal.session_id,
    }


@router.post("/logout")
def logout(principal: Principal = Depends(current_principal)) -> dict:
    with transaction(immediate=True) as connection:
        AuthService(connection).logout(principal)
    return {"message": "已退出"}
