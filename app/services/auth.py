from __future__ import annotations

import os
import sqlite3
from datetime import timedelta

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import AccountLockedError, AuthenticationError, ConflictError, SessionExpiredError
from app.core.security import Principal, generate_token, hash_password, normalize_username, token_digest, verify_password
from app.repositories.identity import SessionRepository, UserRepository
from app.services.audit import AuditContext, AuditService


class AuthService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.users = UserRepository(connection)
        self.sessions = SessionRepository(connection)
        self.audit = AuditService(connection, self.clock)
        self.failure_limit = int(os.getenv("TOWNSHIP_LOGIN_FAILURE_LIMIT", "5"))
        self.lock_minutes = int(os.getenv("TOWNSHIP_LOGIN_LOCK_MINUTES", "30"))
        self.session_minutes = int(os.getenv("TOWNSHIP_SESSION_TTL_MINUTES", "480"))

    def bootstrap_admin(self, username: str, password: str, display_name: str) -> dict:
        normalized = normalize_username(username)
        if self.connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            raise ConflictError("系统已经存在用户，不能再次初始化管理员")
        now = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "INSERT INTO users(username,password_hash,display_name,status,password_changed_at,created_at,updated_at) "
            "VALUES(?,?,?,'active',?,?,?)",
            (normalized, hash_password(password), display_name.strip(), now, now, now),
        )
        user_id = int(cursor.lastrowid)
        role_id = int(self.connection.execute("SELECT id FROM roles WHERE code='administrator'").fetchone()[0])
        self.connection.execute(
            "INSERT INTO user_roles(user_id,role_id,assigned_by,assigned_at) VALUES(?,?,?,?)",
            (user_id, role_id, user_id, now),
        )
        self.audit.record(
            AuditContext(user_id, display_name),
            action="system.bootstrap",
            resource_type="user",
            resource_id=user_id,
            after={"username": normalized, "display_name": display_name},
        )
        return self.users.require(user_id)

    def login(self, username: str, password: str, client_label: str) -> tuple[str, dict]:
        normalized = normalize_username(username)
        user = self.users.by_username(normalized)
        now = self.clock.now()
        if user is None:
            raise AuthenticationError("用户名或密码错误")
        locked_until = from_storage(user.get("locked_until"))
        if locked_until and locked_until > now:
            self._deny(AccountLockedError("账号暂时锁定"), user, {"lock_active": True, "client_label": client_label})
        if user["status"] == "disabled":
            self._deny(AuthenticationError("账号已停用"), user, {"disabled": True, "client_label": client_label})
        if not verify_password(password, user["password_hash"]):
            failures = int(user["failed_login_count"]) + 1
            lock_at = None
            status = user["status"]
            locked_now = False
            if failures >= self.failure_limit:
                lock_at = to_storage(now + timedelta(minutes=self.lock_minutes))
                status = "locked"
                locked_now = True
            self.connection.execute(
                "UPDATE users SET failed_login_count=?,locked_until=?,status=?,updated_at=? WHERE id=?",
                (failures, lock_at, status, to_storage(now), user["id"]),
            )
            self._deny(
                AuthenticationError("用户名或密码错误"),
                user,
                {
                    "failure_count": failures,
                    "locked": locked_now,
                    "locked_until": lock_at,
                    "client_label": client_label,
                },
            )
        token = generate_token()
        expires_at = now + timedelta(minutes=self.session_minutes)
        cursor = self.connection.execute(
            "INSERT INTO sessions(user_id,token_digest,issued_at,expires_at,last_seen_at,client_label) "
            "VALUES(?,?,?,?,?,?)",
            (user["id"], token_digest(token), to_storage(now), to_storage(expires_at), to_storage(now), client_label),
        )
        session_id = int(cursor.lastrowid)
        self.connection.execute(
            "UPDATE users SET failed_login_count=0,locked_until=NULL,status='active',updated_at=? WHERE id=?",
            (to_storage(now), user["id"]),
        )
        unlock_request = self.connection.execute(
            "SELECT id FROM unlock_requests WHERE target_user_id=? AND status='approved' "
            "AND first_login_at IS NULL ORDER BY id DESC LIMIT 1",
            (user["id"],),
        ).fetchone()
        login_metadata = {"client_label": client_label}
        if unlock_request is not None:
            unlock_request_id = int(unlock_request["id"])
            updated = self.connection.execute(
                "UPDATE unlock_requests SET first_login_at=?,first_login_session_id=? "
                "WHERE id=? AND first_login_at IS NULL",
                (to_storage(now), session_id, unlock_request_id),
            )
            if updated.rowcount:
                login_metadata["unlock_request_id"] = unlock_request_id
        self.audit.record(
            AuditContext(user["id"], user["display_name"]),
            action="auth.login",
            resource_type="session",
            resource_id=session_id,
            metadata=login_metadata,
        )
        return token, {"expires_at": to_storage(expires_at), "user": user, "permissions": sorted(self.users.permissions(user["id"]))}

    def _deny(self, error: AuthenticationError, user: dict, metadata: dict) -> None:
        """记录一次被拒绝的登录尝试，然后抛出给定异常（由路由提交后再向客户端返回）。"""
        self.audit.record(
            AuditContext(user["id"], user["display_name"]),
            action="auth.login",
            resource_type="session",
            outcome="denied",
            metadata=metadata,
        )
        raise error

    def principal(self, token: str) -> Principal:
        session = self.sessions.active_by_digest(token_digest(token))
        if session is None:
            raise AuthenticationError("会话不存在或已退出")
        now = self.clock.now()
        expires_at = from_storage(session["expires_at"])
        if expires_at is None or expires_at <= now:
            self.connection.execute(
                "UPDATE sessions SET revoked_at=?,revoke_reason='expired' WHERE id=?",
                (to_storage(now), session["id"]),
            )
            raise SessionExpiredError("会话已过期")
        user = self.users.require(session["user_id"])
        if user["status"] != "active":
            raise AuthenticationError("账号不可用")
        self.connection.execute("UPDATE sessions SET last_seen_at=? WHERE id=?", (to_storage(now), session["id"]))
        return Principal(
            user_id=user["id"],
            username=user["username"],
            display_name=user["display_name"],
            department_id=user["department_id"],
            permissions=frozenset(self.users.permissions(user["id"])),
            session_id=session["id"],
        )

    def logout(self, principal: Principal) -> None:
        now = to_storage(self.clock.now())
        self.connection.execute(
            "UPDATE sessions SET revoked_at=?,revoke_reason='logout' WHERE id=? AND revoked_at IS NULL",
            (now, principal.session_id),
        )
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="auth.logout",
            resource_type="session",
            resource_id=principal.session_id,
        )
