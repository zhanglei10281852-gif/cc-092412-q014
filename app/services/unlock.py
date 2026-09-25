from __future__ import annotations

import sqlite3
from datetime import timedelta

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationError
from app.core.security import Principal, normalize_username
from app.repositories.identity import UserRepository
from app.services.audit import AuditContext, AuditService

TERMINAL_STATUSES = {"approved", "rejected", "withdrawn", "expired", "terminated"}
PENDING = "pending"

HIGH_PRIVILEGE_ROLES = {"administrator"}
SENSITIVE_PERMISSIONS = {"*", "users.write", "roles.write", "unlocks.approve"}


class UnlockService:
    """带双人审批、有效期与目标会话范围的紧急解锁申请。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.users = UserRepository(connection)
        self.audit = AuditService(connection, self.clock)

    # ------------------------------------------------------------------ 申请

    def sweep(self, now_dt=None) -> list[int]:
        """把已过期、或审批链已失效的待决申请收敛为唯一终态。

        必须在写事务之外（autocommit）调用：这些维护性终态不能依附于随后可能被
        回滚的业务事务。返回被收敛的申请 id。
        """
        now_dt = now_dt or self.clock.now()
        now = to_storage(now_dt)
        pending = self.connection.execute(
            "SELECT id,target_user_id,expires_at,first_approver_user_id "
            "FROM unlock_requests WHERE status='pending'",
        ).fetchall()
        changed: list[int] = []
        for row in pending:
            request_id = int(row["id"])
            target_user_id = int(row["target_user_id"])
            if row["expires_at"] <= now:
                cursor = self.connection.execute(
                    "UPDATE unlock_requests SET status='expired',decided_at=?,updated_at=?,"
                    "decision_reason='有效期届满未完成审批' WHERE id=? AND status='pending'",
                    (now, now, request_id),
                )
                if cursor.rowcount:
                    self.audit.record(
                        AuditContext(None, "system"),
                        action="unlock.request.expire",
                        resource_type="unlock_request",
                        resource_id=request_id,
                        outcome="denied",
                        metadata={"target_user_id": target_user_id},
                    )
                    changed.append(request_id)
            elif row["first_approver_user_id"] is not None and not self._approver_effective(int(row["first_approver_user_id"])):
                cursor = self.connection.execute(
                    "UPDATE unlock_requests SET status='terminated',decided_at=?,updated_at=?,"
                    "decision_reason='第一审批人权限在完成前失效，申请终止' WHERE id=? AND status='pending'",
                    (now, now, request_id),
                )
                if cursor.rowcount:
                    self.audit.record(
                        AuditContext(None, "system"),
                        action="unlock.request.terminate",
                        resource_type="unlock_request",
                        resource_id=request_id,
                        outcome="failure",
                        metadata={"target_user_id": target_user_id, "reason": "第一审批人权限失效"},
                    )
                    changed.append(request_id)
        return changed

    def create_request(self, principal: Principal, data: dict) -> dict:
        now_dt = self.clock.now()
        username = normalize_username(data["target_username"])
        target = self.users.by_username(username)
        if target is None:
            raise NotFoundError("目标用户不存在")
        if target["status"] == "disabled":
            raise ValidationError("目标账号已停用，紧急解锁仅处理密码锁定，不适用停用账号")
        locked_until = from_storage(target["locked_until"])
        if target["status"] != "locked" or locked_until is None or locked_until <= now_dt:
            raise ValidationError("目标账号当前未处于密码锁定状态，无需紧急解锁")
        if self.connection.execute(
            "SELECT 1 FROM unlock_requests WHERE target_user_id=? AND status='pending'",
            (target["id"],),
        ).fetchone() is not None:
            raise ConflictError("该账号已有待审批的解锁申请")

        scope = data["session_scope"]
        target_session_id: int | None = None
        if scope == "current":
            if principal.user_id != target["id"]:
                raise ValidationError("仅当为本人申请时才能将会话范围限定为当前会话；代办申请必须使目标全部旧会话失效")
            target_session_id = principal.session_id
            session = self.connection.execute(
                "SELECT user_id FROM sessions WHERE id=? AND revoked_at IS NULL",
                (target_session_id,),
            ).fetchone()
            if session is None or session["user_id"] != target["id"]:
                raise ValidationError("当前会话已失效，不能作为会话范围")

        now = to_storage(now_dt)
        expires_at = to_storage(now_dt + timedelta(minutes=int(data["validity_minutes"])))
        requires_second = self._is_high_privilege(target["id"])
        try:
            cursor = self.connection.execute(
                "INSERT INTO unlock_requests(target_user_id,applicant_user_id,reason,session_scope,"
                "target_session_id,status,locked_snapshot,requires_second,expires_at,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    target["id"],
                    principal.user_id,
                    data["reason"].strip(),
                    scope,
                    target_session_id,
                    PENDING,
                    target["locked_until"],
                    1 if requires_second else 0,
                    expires_at,
                    now,
                    now,
                ),
            )
        except sqlite3.IntegrityError:
            # 并发下唯一部分索引兜底：同一目标只允许一条待决申请。
            raise ConflictError("该账号已有待审批的解锁申请") from None
        request_id = int(cursor.lastrowid)
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="unlock.request.create",
            resource_type="unlock_request",
            resource_id=request_id,
            metadata={
                "target_user_id": target["id"],
                "target_username": target["username"],
                "session_scope": scope,
                "target_session_id": target_session_id,
                "validity_minutes": int(data["validity_minutes"]),
                "requires_second": requires_second,
                "locked_until": target["locked_until"],
            },
        )
        return self.detail(request_id, viewer_id=principal.user_id)

    def withdraw(self, principal: Principal, request_id: int, reason: str) -> dict:
        request = self._require_pending(request_id)
        if principal.user_id != request["applicant_user_id"]:
            raise PermissionDeniedError("只有申请人可以撤回解锁申请")
        now = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "UPDATE unlock_requests SET status='withdrawn',decided_by_user_id=?,decided_at=?,"
            "decision_reason=?,updated_at=? WHERE id=? AND status='pending'",
            (principal.user_id, now, reason.strip() or None, now, request_id),
        )
        if not cursor.rowcount:
            raise ConflictError("申请已结束，不能撤回")
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="unlock.request.withdraw",
            resource_type="unlock_request",
            resource_id=request_id,
            metadata={"target_user_id": request["target_user_id"]},
        )
        return self.detail(request_id, viewer_id=principal.user_id)

    # ------------------------------------------------------------------ 审批

    def decide(self, principal: Principal, request_id: int, decision: str, comment: str) -> dict:
        principal.require("unlocks.approve")
        request = self._require_pending(request_id)
        now_dt = self.clock.now()
        target = self.users.require(request["target_user_id"])
        if principal.user_id == request["applicant_user_id"] or principal.user_id == target["id"]:
            raise PermissionDeniedError("审批人必须是不同于申请人和目标账号的安全管理员")
        if not self._approver_effective(principal.user_id):
            raise PermissionDeniedError("审批人的安全审批权限已失效")

        step = 1 if request["first_approver_user_id"] is None else 2
        if step == 2:
            if principal.user_id == request["first_approver_user_id"]:
                raise PermissionDeniedError("第二确认人必须与第一审批人不同")
            if not self._approver_effective(request["first_approver_user_id"]):
                self._terminate_committed(request, "第一审批人权限在完成前失效，申请终止", now_dt)

        now = to_storage(now_dt)
        try:
            self.connection.execute(
                "INSERT INTO unlock_approvals(request_id,step,approver_user_id,decision,comment,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (request_id, step, principal.user_id, decision, comment.strip() or None, now),
            )
        except sqlite3.IntegrityError:
            # 同一步骤已有并发决定落库：终态唯一，后来者只能接受已有结果。
            current = self._require(request_id)
            raise ConflictError(f"申请已处于{current['status']}状态，不能重复决定") from None

        if decision == "rejected":
            self.connection.execute(
                "UPDATE unlock_requests SET status='rejected',first_approver_user_id=COALESCE(first_approver_user_id,?),"
                "first_approved_at=COALESCE(first_approved_at,?),decided_by_user_id=?,decided_at=?,"
                "decision_reason=?,updated_at=? WHERE id=?",
                (
                    principal.user_id if step == 1 else None,
                    now if step == 1 else None,
                    principal.user_id,
                    now,
                    comment.strip() or None,
                    now,
                    request_id,
                ),
            )
            self.audit.record(
                AuditContext(principal.user_id, principal.display_name),
                action="unlock.request.reject",
                resource_type="unlock_request",
                resource_id=request_id,
                outcome="denied",
                metadata={"step": step, "target_user_id": target["id"]},
            )
            return self.detail(request_id, viewer_id=principal.user_id)

        if step == 1:
            self.connection.execute(
                "UPDATE unlock_requests SET first_approver_user_id=?,first_approved_at=?,updated_at=? WHERE id=?",
                (principal.user_id, now, now, request_id),
            )
            self._audit_approval(principal, request_id, target["id"], step=1, final=False)
            if not request["requires_second"]:
                self._finalize(request_id, now_dt, principal)
            return self.detail(request_id, viewer_id=principal.user_id)

        self.connection.execute(
            "UPDATE unlock_requests SET second_approver_user_id=?,second_approved_at=?,updated_at=? WHERE id=?",
            (principal.user_id, now, now, request_id),
        )
        self._audit_approval(principal, request_id, target["id"], step=2, final=False)
        self._finalize(request_id, now_dt, principal)
        return self.detail(request_id, viewer_id=principal.user_id)

    def _finalize(self, request_id: int, now_dt, principal: Principal) -> None:
        """完成第二（或唯一）步批准：仅清除本次锁定并撤销目标范围内的旧会话。"""
        request = self._require(request_id)
        approvers = [request["first_approver_user_id"]]
        if request["requires_second"]:
            approvers.append(request["second_approver_user_id"])
        for approver_id in approvers:
            if not approver_id or not self._approver_effective(int(approver_id)):
                self._terminate_committed(request, "审批人权限在完成前失效，申请终止", now_dt)
        target = self.users.require(request["target_user_id"])
        if target["status"] == "disabled":
            self._terminate_committed(request, "目标账号已被停用，紧急解锁不适用", now_dt)
        locked_until = from_storage(target["locked_until"])
        if target["status"] != "locked" or locked_until is None or target["locked_until"] != request["locked_snapshot"]:
            self._terminate_committed(request, "锁定状态在审批期间已变化，申请终止", now_dt)

        now = to_storage(now_dt)
        self.connection.execute(
            "UPDATE users SET status='active',locked_until=NULL,failed_login_count=0,updated_at=? WHERE id=?",
            (now, target["id"]),
        )
        if request["session_scope"] == "current":
            session_rows = self.connection.execute(
                "SELECT id FROM sessions WHERE id=? AND user_id=? AND revoked_at IS NULL",
                (request["target_session_id"], target["id"]),
            ).fetchall()
        else:
            session_rows = self.connection.execute(
                "SELECT id FROM sessions WHERE user_id=? AND revoked_at IS NULL",
                (target["id"],),
            ).fetchall()
        revoked_ids = [int(row["id"]) for row in session_rows]
        for session_id in revoked_ids:
            self.connection.execute(
                "UPDATE sessions SET revoked_at=?,revoke_reason='unlock_approved' WHERE id=?",
                (now, session_id),
            )
            self.connection.execute(
                "INSERT OR IGNORE INTO unlock_session_revocations(request_id,session_id,revoked_at) VALUES(?,?,?)",
                (request_id, session_id, now),
            )
        self.connection.execute(
            "UPDATE unlock_requests SET status='approved',decided_by_user_id=?,decided_at=?,updated_at=? WHERE id=?",
            (
                request["second_approver_user_id"] or request["first_approver_user_id"],
                now,
                now,
                request_id,
            ),
        )
        self._audit_approval(
            principal,
            request_id,
            target["id"],
            step=2 if request["requires_second"] else 1,
            final=True,
            extra={"session_scope": request["session_scope"], "revoked_session_count": len(revoked_ids)},
        )

    # ------------------------------------------------------------------ 查询

    def list_requests(self, principal: Principal, *, status: str | None, target_user_id: int | None, limit: int, offset: int) -> tuple[list[dict], int]:
        principal.require("unlocks.read")
        self.sweep()
        return self._query(status=status, target_user_id=target_user_id, limit=limit, offset=offset, viewer_id=principal.user_id)

    def list_own(self, principal: Principal, *, status: str | None, limit: int, offset: int) -> tuple[list[dict], int]:
        self.sweep()
        return self._query(status=status, target_user_id=None, limit=limit, offset=offset, viewer_id=principal.user_id, applicant_user_id=principal.user_id)

    def detail(self, request_id: int, *, viewer_id: int | None = None, principal: Principal | None = None) -> dict:
        self.sweep()
        request = self._require(request_id)
        if principal is not None:
            if principal.user_id != request["applicant_user_id"] and not principal.can("unlocks.read"):
                raise PermissionDeniedError("只能查看本人发起的解锁申请")
            viewer_id = principal.user_id
        return self._serialize(request, viewer_id)

    def _query(self, *, status, target_user_id, limit, offset, viewer_id, applicant_user_id=None) -> tuple[list[dict], int]:
        conditions = []
        params: list = []
        if status:
            if status not in {"pending", *TERMINAL_STATUSES}:
                raise ValidationError("不支持的申请状态筛选")
            conditions.append("r.status=?")
            params.append(status)
        if target_user_id is not None:
            conditions.append("r.target_user_id=?")
            params.append(target_user_id)
        if applicant_user_id is not None:
            conditions.append("r.applicant_user_id=?")
            params.append(applicant_user_id)
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        total = int(self.connection.execute(f"SELECT COUNT(*) FROM unlock_requests r{where}", tuple(params)).fetchone()[0])
        query_params = [*params, limit, offset]
        rows = self.connection.execute(
            f"SELECT r.* FROM unlock_requests r{where} ORDER BY r.id DESC LIMIT ? OFFSET ?",
            tuple(query_params),
        ).fetchall()
        return [self._serialize(dict(row), viewer_id) for row in rows], total

    # ------------------------------------------------------------------ 内部

    def _audit_approval(self, principal: Principal, request_id: int, target_user_id: int, *, step: int, final: bool, extra: dict | None = None) -> None:
        metadata = {"step": step, "final": final, "target_user_id": target_user_id}
        if extra:
            metadata.update(extra)
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="unlock.request.approve",
            resource_type="unlock_request",
            resource_id=request_id,
            metadata=metadata,
        )

    def _terminate_committed(self, request: dict, reason: str, now_dt) -> None:
        """写入终止终态并独立提交，再以 409 通知调用方，确保终态不被外层事务回滚。"""
        now = to_storage(now_dt)
        cursor = self.connection.execute(
            "UPDATE unlock_requests SET status='terminated',decided_at=?,decision_reason=?,updated_at=? "
            "WHERE id=? AND status='pending'",
            (now, reason, now, request["id"]),
        )
        if cursor.rowcount:
            self.audit.record(
                AuditContext(None, "system"),
                action="unlock.request.terminate",
                resource_type="unlock_request",
                resource_id=request["id"],
                outcome="failure",
                metadata={"target_user_id": request["target_user_id"], "reason": reason},
            )
        self.connection.commit()
        raise ConflictError(reason)

    def _is_high_privilege(self, user_id: int) -> bool:
        role_codes = {row["code"] for row in self.users.roles(user_id)}
        if role_codes & HIGH_PRIVILEGE_ROLES:
            return True
        return bool(self.users.permissions(user_id) & SENSITIVE_PERMISSIONS)

    def _approver_effective(self, user_id: int) -> bool:
        user = self.users.get(user_id)
        if user is None or user["status"] != "active":
            return False
        permissions = self.users.permissions(user_id)
        return "*" in permissions or "unlocks.approve" in permissions

    def _require(self, request_id: int) -> dict:
        row = self.connection.execute("SELECT * FROM unlock_requests WHERE id=?", (request_id,)).fetchone()
        if row is None:
            raise NotFoundError("解锁申请不存在")
        return dict(row)

    def _require_pending(self, request_id: int) -> dict:
        request = self._require(request_id)
        if request["status"] != PENDING:
            raise ConflictError(f"申请已处于{request['status']}状态，不能再次操作")
        now_dt = self.clock.now()
        if request["expires_at"] <= to_storage(now_dt):
            # 有效期届满：写入 expired 终态并独立提交，避免随调用方事务回滚。
            now = to_storage(now_dt)
            cursor = self.connection.execute(
                "UPDATE unlock_requests SET status='expired',decided_at=?,updated_at=?,"
                "decision_reason='有效期届满未完成审批' WHERE id=? AND status='pending'",
                (now, now, request_id),
            )
            if cursor.rowcount:
                self.audit.record(
                    AuditContext(None, "system"),
                    action="unlock.request.expire",
                    resource_type="unlock_request",
                    resource_id=request_id,
                    outcome="denied",
                    metadata={"target_user_id": request["target_user_id"]},
                )
            self.connection.commit()
            raise ConflictError("申请已超过有效期，不能继续审批")
        return request

    def _serialize(self, request: dict, viewer_id: int | None) -> dict:
        approvals = self.connection.execute(
            "SELECT step,approver_user_id,decision,comment,created_at FROM unlock_approvals "
            "WHERE request_id=? ORDER BY step",
            (request["id"],),
        ).fetchall()
        request["approvals"] = [dict(row) for row in approvals]
        names = {
            request["target_user_id"]: None,
            request["applicant_user_id"]: None,
        }
        for key in ("first_approver_user_id", "second_approver_user_id", "decided_by_user_id"):
            if request.get(key) is not None:
                names[int(request[key])] = None
        for user_id in names:
            user = self.users.get(user_id)
            names[user_id] = user["username"] if user else None
        request["target_username"] = names[request["target_user_id"]]
        request["applicant_username"] = names[request["applicant_user_id"]]
        request["first_approver_username"] = names.get(request["first_approver_user_id"])
        request["second_approver_username"] = names.get(request["second_approver_user_id"])
        request["requires_second"] = bool(request["requires_second"])
        revocation_rows = self.connection.execute(
            "SELECT session_id,revoked_at FROM unlock_session_revocations WHERE request_id=?",
            (request["id"],),
        ).fetchall()
        request["revoked_sessions"] = [dict(row) for row in revocation_rows]
        request["can_withdraw"] = request["status"] == PENDING and viewer_id == request["applicant_user_id"]
        return request
