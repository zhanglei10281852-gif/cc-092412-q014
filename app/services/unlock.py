from __future__ import annotations

import os
import sqlite3
from datetime import timedelta

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationError
from app.core.security import Principal, normalize_username
from app.repositories.identity import SessionRepository, UserRepository
from app.repositories.unlock import UnlockRequestRepository
from app.services.audit import AuditContext, AuditService

# 目标账号权限集合与下列权限相交时视为高权限账号，需要第二名审批人确认
HIGH_PRIVILEGE_PERMISSIONS = frozenset({"users.write", "roles.write"})

TERMINAL_STATUSES = frozenset({"approved", "rejected", "withdrawn", "expired", "terminated"})

SESSION_SCOPES = frozenset({"all", "pre_lock", "none"})


class UnlockRequestService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.users = UserRepository(connection)
        self.sessions = SessionRepository(connection)
        self.requests = UnlockRequestRepository(connection)
        self.audit = AuditService(connection, self.clock)
        self.lock_minutes = int(os.getenv("TOWNSHIP_LOGIN_LOCK_MINUTES", "30"))

    @staticmethod
    def correlation_id(request_id: int) -> str:
        return f"unlock-request:{request_id}"

    def create_request(
        self,
        principal: Principal,
        *,
        target_username: str,
        reason: str,
        valid_minutes: int,
        session_scope: str,
    ) -> dict:
        principal.require("unlock.request")
        if session_scope not in SESSION_SCOPES:
            raise ValidationError("会话范围必须是 all、pre_lock 或 none")
        if not reason.strip():
            raise ValidationError("申请原因不能为空")
        target = self.users.by_username(normalize_username(target_username))
        if target is None:
            raise NotFoundError("目标用户不存在")
        now = self.clock.now()
        locked_until = from_storage(target["locked_until"])
        if target["status"] != "locked" or locked_until is None or locked_until <= now:
            raise ConflictError("目标账号当前不处于密码锁定状态")
        if self.requests.pending_for_target(target["id"]) is not None:
            raise ConflictError("该账号已存在待审批的解锁申请")
        requires_second = bool(self.users.permissions(target["id"]) & HIGH_PRIVILEGE_PERMISSIONS)
        now_text = to_storage(now)
        cursor = self.connection.execute(
            "INSERT INTO unlock_requests(target_user_id,applicant_user_id,reason,session_scope,status,"
            "requires_second,target_locked_until,target_failed_count,expires_at,created_at,updated_at) "
            "VALUES(?,?,?,?,'pending',?,?,?,?,?,?)",
            (
                target["id"],
                principal.user_id,
                reason.strip(),
                session_scope,
                1 if requires_second else 0,
                to_storage(locked_until),
                int(target["failed_login_count"]),
                to_storage(now + timedelta(minutes=valid_minutes)),
                now_text,
                now_text,
            ),
        )
        request_id = int(cursor.lastrowid)
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name, self.correlation_id(request_id)),
            action="unlock_request.create",
            resource_type="unlock_request",
            resource_id=request_id,
            after={"status": "pending", "session_scope": session_scope},
            metadata={
                "target_user_id": target["id"],
                "target_username": target["username"],
                "requires_second": requires_second,
                "target_failed_count": int(target["failed_login_count"]),
                "target_locked_until": to_storage(locked_until),
            },
        )
        return self.detail(request_id)

    def decide(self, principal: Principal, request_id: int, *, decision: str, note: str | None) -> dict:
        principal.require("unlock.approve")
        if decision not in {"approve", "reject"}:
            raise ValidationError("审批决定必须是 approve 或 reject")
        note_text = (note or "").strip() or None
        if decision == "reject" and note_text is None:
            raise ValidationError("拒绝时必须填写审批意见")
        request = self._pending_or_conflict(request_id)
        if principal.user_id == request["applicant_user_id"]:
            raise PermissionDeniedError("不能审批本人提交的解锁申请")
        approvals = self.requests.approvals(request_id)
        if any(item["approver_user_id"] == principal.user_id for item in approvals):
            raise ConflictError("当前审批人已对该申请作出过决定，不能重复审批")
        lapsed = [item for item in approvals if not self._approver_valid(item["approver_user_id"])]
        if lapsed:
            # 审批人权限在完成前失效：终止申请并落库，不再接受本次决定
            self._terminate(request_id, principal, lapsed)
            return self.detail(request_id)
        now = self.clock.now()
        now_text = to_storage(now)
        step = len(approvals) + 1
        self.connection.execute(
            "INSERT INTO unlock_request_approvals(request_id,approver_user_id,step,decision,note,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (request_id, principal.user_id, step, decision, note_text, now_text),
        )
        context = AuditContext(principal.user_id, principal.display_name, self.correlation_id(request_id))
        if decision == "reject":
            self._finalize(request_id, "rejected", decided_by=principal.user_id, note=note_text, now_text=now_text)
            self.audit.record(
                context,
                action="unlock_request.reject",
                resource_type="unlock_request",
                resource_id=request_id,
                before={"status": "pending"},
                after={"status": "rejected"},
                metadata={"target_user_id": request["target_user_id"], "step": step},
            )
            return self.detail(request_id)
        final = not request["requires_second"] or step >= 2
        if not final:
            self.connection.execute(
                "UPDATE unlock_requests SET updated_at=? WHERE id=? AND status='pending'",
                (now_text, request_id),
            )
            self.audit.record(
                context,
                action="unlock_request.approve",
                resource_type="unlock_request",
                resource_id=request_id,
                metadata={"target_user_id": request["target_user_id"], "step": step, "final": False},
            )
            return self.detail(request_id)
        executed = self._execute_unlock(request, now)
        self._finalize(
            request_id,
            "approved",
            decided_by=principal.user_id,
            note=note_text,
            now_text=now_text,
            executed_at=now_text,
            revoked_session_count=executed["revoked_sessions"],
        )
        self.audit.record(
            context,
            action="unlock_request.approve",
            resource_type="unlock_request",
            resource_id=request_id,
            metadata={"target_user_id": request["target_user_id"], "step": step, "final": True},
        )
        self.audit.record(
            context,
            action="unlock_request.execute",
            resource_type="unlock_request",
            resource_id=request_id,
            before={"status": "pending"},
            after={"status": "approved"},
            metadata={
                "target_user_id": request["target_user_id"],
                "cleared_lock_until": request["target_locked_until"],
                "session_scope": request["session_scope"],
                "revoked_session_count": executed["revoked_sessions"],
            },
        )
        return self.detail(request_id)

    def withdraw(self, principal: Principal, request_id: int) -> dict:
        request = self._pending_or_conflict(request_id)
        if principal.user_id != request["applicant_user_id"]:
            raise PermissionDeniedError("只有申请人可以撤回解锁申请")
        now_text = to_storage(self.clock.now())
        self._finalize(request_id, "withdrawn", decided_by=principal.user_id, note=None, now_text=now_text)
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name, self.correlation_id(request_id)),
            action="unlock_request.withdraw",
            resource_type="unlock_request",
            resource_id=request_id,
            before={"status": "pending"},
            after={"status": "withdrawn"},
            metadata={"target_user_id": request["target_user_id"]},
        )
        return self.detail(request_id)

    def detail(self, request_id: int) -> dict:
        request = self.requests.require(request_id)
        return self._enrich(request)

    def get_detail(self, principal: Principal, request_id: int) -> dict:
        self._expire_if_due(request_id)
        request = self.requests.get(request_id)
        if request is None:
            raise NotFoundError("解锁申请不存在")
        if not principal.can("unlock.read") and principal.user_id != request["applicant_user_id"]:
            raise PermissionDeniedError("缺少权限：unlock.read")
        return self._enrich(request)

    def expire_due(self) -> int:
        now_text = to_storage(self.clock.now())
        rows = self.connection.execute(
            "SELECT id,target_user_id FROM unlock_requests WHERE status='pending' AND expires_at<=?",
            (now_text,),
        ).fetchall()
        for row in rows:
            if self._expire_row(row["id"], now_text):
                self.audit.record(
                    AuditContext(None, "system", self.correlation_id(row["id"])),
                    action="unlock_request.expire",
                    resource_type="unlock_request",
                    resource_id=row["id"],
                    before={"status": "pending"},
                    after={"status": "expired"},
                    metadata={"target_user_id": row["target_user_id"]},
                )
        return len(rows)

    def terminate_lapsed(self, actor: AuditContext) -> list[int]:
        terminated: list[int] = []
        for request in self.requests.pending_with_approvals():
            approvals = self.requests.approvals(request["id"])
            lapsed = [item for item in approvals if not self._approver_valid(item["approver_user_id"])]
            if lapsed and self._terminate(request["id"], None, lapsed, actor=actor):
                terminated.append(request["id"])
        return terminated

    def _terminate(
        self,
        request_id: int,
        principal: Principal | None,
        lapsed: list[dict],
        *,
        actor: AuditContext | None = None,
    ) -> bool:
        now_text = to_storage(self.clock.now())
        lapsed_ids = sorted({int(item["approver_user_id"]) for item in lapsed})
        note = f"审批人权限在完成前失效：{','.join(str(item) for item in lapsed_ids)}"
        cursor = self.connection.execute(
            "UPDATE unlock_requests SET status='terminated',decided_at=?,decision_note=?,updated_at=? "
            "WHERE id=? AND status='pending'",
            (now_text, note, now_text, request_id),
        )
        if cursor.rowcount != 1:
            return False
        if actor is None:
            actor = AuditContext(principal.user_id, principal.display_name) if principal else AuditContext(None, "system")
        actor = AuditContext(actor.actor_user_id, actor.actor_name, self.correlation_id(request_id))
        target = self.connection.execute("SELECT target_user_id FROM unlock_requests WHERE id=?", (request_id,)).fetchone()
        self.audit.record(
            actor,
            action="unlock_request.terminate",
            resource_type="unlock_request",
            resource_id=request_id,
            before={"status": "pending"},
            after={"status": "terminated"},
            metadata={"lapsed_approver_user_ids": lapsed_ids, "target_user_id": target["target_user_id"] if target else None},
        )
        return True

    def _execute_unlock(self, request: dict, now) -> dict:
        target = self.users.require(request["target_user_id"])
        if target["locked_until"] != request["target_locked_until"]:
            raise ConflictError("账号锁定状态已变化，本次申请不再适用，请重新提交")
        now_text = to_storage(now)
        self.connection.execute(
            "UPDATE users SET failed_login_count=0,locked_until=NULL,"
            "status=CASE WHEN status='locked' THEN 'active' ELSE status END,updated_at=? WHERE id=?",
            (now_text, target["id"]),
        )
        revoked = 0
        scope = request["session_scope"]
        if scope == "all":
            revoked = self.sessions.revoke_user_sessions(target["id"], now_text, "unlock_request")
        elif scope == "pre_lock":
            lock_started = from_storage(request["target_locked_until"]) - timedelta(minutes=self.lock_minutes)
            cursor = self.connection.execute(
                "UPDATE sessions SET revoked_at=?,revoke_reason='unlock_request' "
                "WHERE user_id=? AND revoked_at IS NULL AND issued_at<=?",
                (now_text, target["id"], to_storage(lock_started)),
            )
            revoked = cursor.rowcount
        return {"revoked_sessions": revoked}

    def _pending_or_conflict(self, request_id: int) -> dict:
        request = self.requests.get(request_id)
        if request is None:
            raise NotFoundError("解锁申请不存在")
        self._expire_if_due(request_id)
        request = self.requests.require(request_id)
        if request["status"] != "pending":
            raise ConflictError(f"解锁申请已处于终态：{request['status']}")
        return request

    def _expire_if_due(self, request_id: int) -> None:
        request = self.requests.get(request_id)
        if request is None or request["status"] != "pending":
            return
        expires_at = from_storage(request["expires_at"])
        if expires_at is None or expires_at > self.clock.now():
            return
        now_text = to_storage(self.clock.now())
        if self._expire_row(request_id, now_text):
            self.audit.record(
                AuditContext(None, "system", self.correlation_id(request_id)),
                action="unlock_request.expire",
                resource_type="unlock_request",
                resource_id=request_id,
                before={"status": "pending"},
                after={"status": "expired"},
                metadata={"target_user_id": request["target_user_id"]},
            )

    def _expire_row(self, request_id: int, now_text: str) -> bool:
        cursor = self.connection.execute(
            "UPDATE unlock_requests SET status='expired',decided_at=?,decision_note='有效期已过',updated_at=? "
            "WHERE id=? AND status='pending'",
            (now_text, now_text, request_id),
        )
        return cursor.rowcount == 1

    def _finalize(
        self,
        request_id: int,
        status: str,
        *,
        decided_by: int | None,
        note: str | None,
        now_text: str,
        executed_at: str | None = None,
        revoked_session_count: int | None = None,
    ) -> None:
        if status not in TERMINAL_STATUSES:
            raise ValidationError("非法的解锁申请终态")
        cursor = self.connection.execute(
            "UPDATE unlock_requests SET status=?,decided_at=?,decided_by=?,decision_note=?,"
            "executed_at=?,revoked_session_count=?,updated_at=? WHERE id=? AND status='pending'",
            (status, now_text, decided_by, note, executed_at, revoked_session_count, now_text, request_id),
        )
        if cursor.rowcount != 1:
            raise ConflictError("解锁申请已被并发处理，终态唯一")

    def _approver_valid(self, user_id: int) -> bool:
        user = self.users.get(user_id)
        if user is None or user["status"] != "active":
            return False
        return "unlock.approve" in self.users.permissions(user_id)

    def _enrich(self, request: dict) -> dict:
        target = self.users.get(request["target_user_id"])
        applicant = self.users.get(request["applicant_user_id"])
        decided_by = self.users.get(request["decided_by"]) if request["decided_by"] is not None else None
        result = dict(request)
        result["target_username"] = target["username"] if target else None
        result["target_display_name"] = target["display_name"] if target else None
        result["applicant_username"] = applicant["username"] if applicant else None
        result["applicant_display_name"] = applicant["display_name"] if applicant else None
        result["decided_by_username"] = decided_by["username"] if decided_by else None
        result["requires_second"] = bool(request["requires_second"])
        result["correlation_id"] = self.correlation_id(request["id"])
        result["approvals"] = self.requests.approvals(request["id"])
        return result
