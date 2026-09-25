from __future__ import annotations

from fastapi import Header

from app.core.clock import from_storage, to_storage
from app.core.errors import AuthenticationError
from app.core.security import Principal, token_digest
from app.database import get_connection
from app.repositories.identity import UserRepository
from app.services.auth import AuthService


def current_principal(authorization: str | None = Header(default=None)) -> Principal:
    if not authorization or not authorization.startswith("Bearer "):
        raise AuthenticationError("缺少 Bearer 会话令牌")
    token = authorization[7:].strip()
    if not token:
        raise AuthenticationError("会话令牌为空")
    return AuthService(get_connection()).principal(token)


def current_principal_allow_locked(authorization: str | None = Header(default=None)) -> Principal:
    """紧急解锁申请专用依赖：放行因连续输错密码而锁定、但会话令牌本身仍有效的用户。"""
    if not authorization or not authorization.startswith("Bearer "):
        raise AuthenticationError("缺少 Bearer 会话令牌")
    token = authorization[7:].strip()
    if not token:
        raise AuthenticationError("会话令牌为空")
    connection = get_connection()
    session = connection.execute(
        "SELECT * FROM sessions WHERE token_digest=? AND revoked_at IS NULL",
        (token_digest(token),),
    ).fetchone()
    if session is None:
        raise AuthenticationError("会话不存在或已退出")
    now = AuthService(connection).clock.now()
    expires_at = from_storage(session["expires_at"])
    if expires_at is None or expires_at <= now:
        connection.execute(
            "UPDATE sessions SET revoked_at=?,revoke_reason='expired' WHERE id=?",
            (to_storage(now), session["id"]),
        )
        raise AuthenticationError("会话已过期")
    users = UserRepository(connection)
    user = users.require(session["user_id"])
    if user["status"] == "disabled":
        raise AuthenticationError("账号已停用")
    connection.execute("UPDATE sessions SET last_seen_at=? WHERE id=?", (to_storage(now), session["id"]))
    return Principal(
        user_id=user["id"],
        username=user["username"],
        display_name=user["display_name"],
        department_id=user["department_id"],
        permissions=frozenset(users.permissions(user["id"])),
        session_id=session["id"],
    )
