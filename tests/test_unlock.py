from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.core.clock import FrozenClock
from app.core.errors import ConflictError
from app.core.security import Principal
from app.database import get_connection, transaction
from app.services.unlock import UnlockService


PASSWORD = "Clerk!234567"


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _login(client, username: str, password: str = PASSWORD, label: str = "t") -> str:
    response = client.post("/api/auth/login", json={"username": username, "password": password, "client_label": label})
    assert response.status_code == 200, response.text
    return response.json()["token"]


def _make_user(client, admin_headers, username: str, roles: list[str], password: str = PASSWORD) -> int:
    response = client.post(
        "/api/users",
        headers=admin_headers,
        json={"username": username, "password": password, "display_name": username, "role_codes": roles},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _lock(client, username: str, password: str = PASSWORD) -> None:
    for _ in range(5):
        client.post("/api/auth/login", json={"username": username, "password": "definitely-wrong", "client_label": "kiosk"})
    locked = client.post("/api/auth/login", json={"username": username, "password": password, "client_label": "kiosk"})
    assert locked.status_code == 401
    assert locked.json()["error"]["code"] == "account_locked"


def _principal(user_id: int, permissions: set[str] | None = None) -> Principal:
    return Principal(
        user_id=user_id,
        username=f"user{user_id}",
        display_name=f"用户{user_id}",
        department_id=None,
        permissions=frozenset(permissions or {"unlocks.read", "unlocks.approve"}),
        session_id=1,
    )


@pytest.fixture()
def people(client, admin):
    ah = admin["headers"]
    sec1_id = _make_user(client, ah, "sec.one", ["security_admin"])
    sec2_id = _make_user(client, ah, "sec.two", ["security_admin"])
    duty_id = _make_user(client, ah, "duty.guy", ["clerk"])
    return {
        "admin_headers": ah,
        "sec1_id": sec1_id,
        "sec2_id": sec2_id,
        "duty_id": duty_id,
        "sec1": _headers(_login(client, "sec.one")),
        "sec2": _headers(_login(client, "sec.two")),
    }


def _file(client, headers, *, target="duty.guy", scope="all", minutes=30, reason="节假日值班连续输错密码，申请紧急解锁"):
    response = client.post(
        "/api/unlock-requests",
        headers=headers,
        json={"target_username": target, "reason": reason, "validity_minutes": minutes, "session_scope": scope},
    )
    return response


# ---------------------------------------------------------------- 锁定前提

def test_failed_logins_persist_lock_and_audit(client, people):
    """修复既有缺陷：认证失败必须落库，达到阈值真正锁定并留下带锁定标记的审计。"""
    _lock(client, "duty.guy")
    row = get_connection().execute(
        "SELECT status,failed_login_count,locked_until FROM users WHERE username='duty.guy'"
    ).fetchone()
    assert row["status"] == "locked"
    assert row["failed_login_count"] == 5
    assert row["locked_until"]
    marker = get_connection().execute(
        "SELECT COUNT(*) FROM audit_events e JOIN users u ON u.id=e.actor_user_id "
        "WHERE u.username='duty.guy' AND e.action='auth.login' AND e.outcome='denied' "
        "AND e.metadata_json LIKE '%\"locked\": true%'"
    ).fetchone()[0]
    assert marker == 1


# ---------------------------------------------------------------- 申请校验

def test_locked_user_files_request_with_old_session(client, people):
    old_token = _login(client, "duty.guy")
    _lock(client, "duty.guy")
    # 旧会话不能访问普通接口
    assert client.get("/api/auth/me", headers=_headers(old_token)).status_code == 401
    # 但可以发起解锁申请
    response = _file(client, _headers(old_token))
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "pending"
    assert body["requires_second"] is False
    assert body["session_scope"] == "all"
    assert body["applicant_username"] == "duty.guy"
    assert body["can_withdraw"] is True


def test_request_requires_actual_lock_and_valid_fields(client, people):
    token = _headers(_login(client, "duty.guy"))
    # 未锁定不能申请
    response = _file(client, token)
    assert response.status_code == 422
    _lock(client, "duty.guy")
    # 有效期越界
    for bad_minutes in (4, 241):
        response = _file(client, token, minutes=bad_minutes)
        assert response.status_code == 422
    # 原因过短
    response = client.post(
        "/api/unlock-requests",
        headers=token,
        json={"target_username": "duty.guy", "reason": "太短", "validity_minutes": 30, "session_scope": "all"},
    )
    assert response.status_code == 422


def test_current_scope_only_for_self_application(client, people):
    _lock(client, "duty.guy")
    # 安全管理员为他人代办时不能指定目标的“当前会话”
    response = _file(client, people["sec1"], scope="current")
    assert response.status_code == 422


def test_duplicate_pending_request_is_rejected(client, people):
    _lock(client, "duty.guy")
    first = _file(client, people["sec1"])
    assert first.status_code == 201
    second = _file(client, people["sec2"])
    assert second.status_code == 409


# ------------------------------------------------------- 单人审批（普通账号）

def test_single_approval_clears_lock_revokes_all_sessions_and_keeps_password(client, people):
    old_token = _login(client, "duty.guy")
    _lock(client, "duty.guy")
    rid = _file(client, _headers(old_token)).json()["id"]
    before = get_connection().execute("SELECT password_hash,password_changed_at FROM users WHERE username='duty.guy'").fetchone()

    decision = client.post(
        f"/api/unlock-requests/{rid}/decision",
        headers=people["sec1"],
        json={"decision": "approved", "comment": "已电话核实本人"},
    )
    assert decision.status_code == 200, decision.text
    body = decision.json()
    assert body["status"] == "approved"
    assert len(body["approvals"]) == 1 and body["approvals"][0]["decision"] == "approved"
    assert len(body["revoked_sessions"]) >= 1

    after = get_connection().execute("SELECT * FROM users WHERE username='duty.guy'").fetchone()
    assert after["status"] == "active"
    assert after["locked_until"] is None
    assert after["password_hash"] == before["password_hash"]
    assert after["password_changed_at"] == before["password_changed_at"]
    # 旧会话全部失效
    assert client.get("/api/auth/me", headers=_headers(old_token)).status_code == 401
    # 原密码可以直接登录
    relogin = client.post("/api/auth/login", json={"username": "duty.guy", "password": PASSWORD, "client_label": "kiosk"})
    assert relogin.status_code == 200


def test_current_session_scope_revokes_only_target_session(client, people):
    token_a = _login(client, "duty.guy", label="console-a")
    token_b = _login(client, "duty.guy", label="console-b")
    _lock(client, "duty.guy")
    rid = _file(client, _headers(token_a), scope="current").json()["id"]
    decision = client.post(f"/api/unlock-requests/{rid}/decision", headers=people["sec1"], json={"decision": "approved"})
    assert decision.status_code == 200
    assert len(decision.json()["revoked_sessions"]) == 1
    # 申请所用会话失效
    assert client.get("/api/auth/me", headers=_headers(token_a)).status_code == 401
    # 另一会话仍然有效（锁定已清除）
    assert client.get("/api/auth/me", headers=_headers(token_b)).status_code == 200


def test_rejection_keeps_account_locked(client, people):
    old_token = _login(client, "duty.guy")
    _lock(client, "duty.guy")
    rid = _file(client, _headers(old_token)).json()["id"]
    decision = client.post(f"/api/unlock-requests/{rid}/decision", headers=people["sec1"], json={"decision": "rejected", "comment": "无法核实"})
    assert decision.json()["status"] == "rejected"
    locked = client.post("/api/auth/login", json={"username": "duty.guy", "password": PASSWORD, "client_label": "k"})
    assert locked.json()["error"]["code"] == "account_locked"
    # 终态唯一：拒绝后不能再批准
    again = client.post(f"/api/unlock-requests/{rid}/decision", headers=people["sec1"], json={"decision": "approved"})
    assert again.status_code == 409


# ------------------------------------------------------- 双人审批（高权限账号）

def _lock_high_privilege_target(client, admin_headers):
    user_id = _make_user(client, admin_headers, "boss.two", ["administrator"], password="Boss!2345678")
    _lock(client, "boss.two", "Boss!2345678")
    return user_id


def test_high_privilege_requires_two_distinct_approvers(client, people):
    _lock_high_privilege_target(client, people["admin_headers"])
    # 申请人是经办员（与审批人不同）
    duty_token = _headers(_login(client, "duty.guy"))
    rid = _file(client, duty_token, target="boss.two", minutes=20).json()["id"]

    first = client.post(f"/api/unlock-requests/{rid}/decision", headers=people["sec1"], json={"decision": "approved"})
    assert first.status_code == 200
    assert first.json()["status"] == "pending"
    assert len(first.json()["approvals"]) == 1
    # 同一人不能二次确认
    assert client.post(f"/api/unlock-requests/{rid}/decision", headers=people["sec1"], json={"decision": "approved"}).status_code == 403
    # 申请人不能当第二确认人
    assert client.post(f"/api/unlock-requests/{rid}/decision", headers=duty_token, json={"decision": "approved"}).status_code == 403
    # 第二人确认后才解锁
    second = client.post(f"/api/unlock-requests/{rid}/decision", headers=people["sec2"], json={"decision": "approved"})
    assert second.status_code == 200
    assert second.json()["status"] == "approved"
    assert second.json()["first_approver_username"] == "sec.one"
    assert second.json()["second_approver_username"] == "sec.two"
    relogin = client.post("/api/auth/login", json={"username": "boss.two", "password": "Boss!2345678", "client_label": "k"})
    assert relogin.status_code == 200


def test_rejection_at_second_step_is_final(client, people):
    _lock_high_privilege_target(client, people["admin_headers"])
    duty_token = _headers(_login(client, "duty.guy"))
    rid = _file(client, duty_token, target="boss.two").json()["id"]
    client.post(f"/api/unlock-requests/{rid}/decision", headers=people["sec1"], json={"decision": "approved"})
    rejected = client.post(f"/api/unlock-requests/{rid}/decision", headers=people["sec2"], json={"decision": "rejected", "comment": "存疑"})
    assert rejected.json()["status"] == "rejected"
    assert rejected.json()["decided_by_user_id"] == people["sec2_id"]
    locked = client.post("/api/auth/login", json={"username": "boss.two", "password": "Boss!2345678", "client_label": "k"})
    assert locked.json()["error"]["code"] == "account_locked"


# ------------------------------------------------------- 权限失效即终止

def test_request_terminates_when_first_approver_loses_permission(client, people):
    _lock_high_privilege_target(client, people["admin_headers"])
    duty_token = _headers(_login(client, "duty.guy"))
    rid = _file(client, duty_token, target="boss.two").json()["id"]
    client.post(f"/api/unlock-requests/{rid}/decision", headers=people["sec1"], json={"decision": "approved"})
    # 第一审批人的安全管理员角色被收回
    replaced = client.put(f"/api/users/{people['sec1_id']}/roles", headers=people["admin_headers"], json={"role_codes": ["clerk"]})
    assert replaced.status_code == 200
    # 第二人尝试决定时，申请已被终止
    with pytest.raises(ConflictError):
        with transaction(immediate=True) as connection:
            UnlockService(connection).decide(_principal(people["sec2_id"]), rid, "approved", "")
    detail = client.get(f"/api/unlock-requests/{rid}", headers=people["sec2"]).json()
    assert detail["status"] == "terminated"
    assert "审批人权限" in detail["decision_reason"]
    # 目标仍处于锁定
    locked = client.post("/api/auth/login", json={"username": "boss.two", "password": "Boss!2345678", "client_label": "k"})
    assert locked.json()["error"]["code"] == "account_locked"


def test_request_terminates_when_target_disabled_during_review(client, people):
    _lock(client, "duty.guy")
    rid = _file(client, people["admin_headers"]).json()["id"]
    client.patch(f"/api/users/{people['duty_id']}", headers=people["admin_headers"], json={"status": "disabled"})
    decision = client.post(f"/api/unlock-requests/{rid}/decision", headers=people["sec1"], json={"decision": "approved"})
    assert decision.status_code == 409
    detail = client.get(f"/api/unlock-requests/{rid}", headers=people["sec1"]).json()
    assert detail["status"] == "terminated"


# ------------------------------------------------------- 撤回与过期

def test_only_applicant_can_withdraw(client, people):
    _lock(client, "duty.guy")
    rid = _file(client, people["sec1"]).json()["id"]
    # 非申请人不能撤回
    assert client.post(f"/api/unlock-requests/{rid}/withdraw", headers=people["sec2"], json={"reason": "x"}).status_code == 403
    withdrawn = client.post(f"/api/unlock-requests/{rid}/withdraw", headers=people["sec1"], json={"reason": "自行恢复"})
    assert withdrawn.json()["status"] == "withdrawn"
    # 撤回后不能再审批
    assert client.post(f"/api/unlock-requests/{rid}/decision", headers=people["sec2"], json={"decision": "approved"}).status_code == 409


def test_request_expires_after_validity_window(client, people):
    _lock(client, "duty.guy")
    rid = _file(client, people["sec1"], minutes=5).json()["id"]
    future = FrozenClock(datetime.now(UTC) + timedelta(minutes=6))
    with pytest.raises(ConflictError):
        with transaction(immediate=True) as connection:
            UnlockService(connection, future).decide(_principal(people["sec1_id"]), rid, "approved", "")
    detail = client.get(f"/api/unlock-requests/{rid}", headers=people["sec1"]).json()
    assert detail["status"] == "expired"
    # 过期后允许就同一账号重新申请
    assert _file(client, people["sec1"], minutes=10).status_code == 201


# ------------------------------------------------------- 权限与可见性

def test_decision_requires_unlock_permission(client, people):
    _lock(client, "duty.guy")
    rid = _file(client, people["sec1"]).json()["id"]
    # 无审批权限的活跃用户不能决定
    _make_user(client, people["admin_headers"], "clerk.two", ["clerk"])
    outsider = _headers(_login(client, "clerk.two"))
    response = client.post(f"/api/unlock-requests/{rid}/decision", headers=outsider, json={"decision": "approved"})
    assert response.status_code == 403


def test_applicant_can_read_own_request_without_audit_permission(client, people):
    old_token = _login(client, "duty.guy")
    _lock(client, "duty.guy")
    rid = _file(client, _headers(old_token)).json()["id"]
    detail = client.get(f"/api/unlock-requests/{rid}", headers=_headers(old_token))
    assert detail.status_code == 200
    # 无 unlocks.read 权限的其他活跃用户不能看申请列表
    _make_user(client, people["admin_headers"], "clerk.two", ["clerk"])
    outsider = _headers(_login(client, "clerk.two"))
    assert client.get("/api/unlock-requests", headers=outsider).status_code == 403
    # 申请人只能看到自己的申请
    mine = client.get("/api/unlock-requests/mine", headers=_headers(old_token))
    assert mine.status_code == 200
    assert {item["id"] for item in mine.json()["data"]} == {rid}


# ------------------------------------------------------- 并发与唯一终态

def test_concurrent_same_step_decision_collapses_to_conflict(client, people):
    """竞争事务已为同一申请写入第一步审批时，后来者的重复决定必须收敛为 409。"""
    _lock_high_privilege_target(client, people["admin_headers"])
    duty_token = _headers(_login(client, "duty.guy"))
    rid = _file(client, duty_token, target="boss.two").json()["id"]
    # 模拟一个并发事务抢先写入第一步审批（但未回填申请主表）
    connection = get_connection()
    now = connection.execute("SELECT datetime('now')").fetchone()[0]
    connection.execute(
        "INSERT INTO unlock_approvals(request_id,step,approver_user_id,decision,comment,created_at) "
        "VALUES(?,?,?,?,?,?)",
        (rid, 1, people["sec1_id"], "approved", None, now),
    )
    connection.commit()
    response = client.post(f"/api/unlock-requests/{rid}/decision", headers=people["sec2"], json={"decision": "approved"})
    assert response.status_code == 409
    # 申请未被解锁，目标仍锁定
    locked = client.post("/api/auth/login", json={"username": "boss.two", "password": "Boss!2345678", "client_label": "k"})
    assert locked.json()["error"]["code"] == "account_locked"


def test_withdrawn_then_recreated_request_follows_fresh_lifecycle(client, people):
    _lock(client, "duty.guy")
    rid = _file(client, people["sec1"]).json()["id"]
    client.post(f"/api/unlock-requests/{rid}/withdraw", headers=people["sec1"], json={"reason": "ok"})
    second = _file(client, people["sec1"], reason="重新发起的解锁申请")
    assert second.status_code == 201
    new_id = second.json()["id"]
    assert new_id != rid
    decision = client.post(f"/api/unlock-requests/{new_id}/decision", headers=people["sec2"], json={"decision": "approved"})
    assert decision.status_code == 200
    assert decision.json()["status"] == "approved"


# ------------------------------------------------------- 审计链

def test_audit_chain_links_failure_request_approvals_and_first_login(client, people):
    old_token = _login(client, "duty.guy", label="holiday-console")
    _lock(client, "duty.guy")
    rid = _file(client, _headers(old_token)).json()["id"]
    client.post(f"/api/unlock-requests/{rid}/decision", headers=people["sec1"], json={"decision": "approved", "comment": "ok"})
    client.post("/api/auth/login", json={"username": "duty.guy", "password": PASSWORD, "client_label": "holiday-console"})

    connection = get_connection()
    denied_lock = connection.execute(
        "SELECT COUNT(*) FROM audit_events e JOIN users u ON u.id=e.actor_user_id "
        "WHERE u.username='duty.guy' AND e.action='auth.login' AND e.outcome='denied' "
        "AND e.metadata_json LIKE '%\"locked\": true%'"
    ).fetchone()[0]
    assert denied_lock == 1
    created = connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE action='unlock.request.create' AND resource_id=?", (str(rid),)
    ).fetchone()[0]
    assert created == 1
    final_approval = connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE action='unlock.request.approve' AND resource_id=? "
        "AND metadata_json LIKE '%\"final\": true%'", (str(rid),)
    ).fetchone()[0]
    assert final_approval == 1
    first_login = connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE action='auth.login' AND outcome='success' "
        "AND metadata_json LIKE ?", (f'%"unlock_request_id": {rid}%',)
    ).fetchone()[0]
    assert first_login == 1
    request = connection.execute("SELECT first_login_at,first_login_session_id FROM unlock_requests WHERE id=?", (rid,)).fetchone()
    assert request["first_login_at"] and request["first_login_session_id"]


def test_only_first_login_after_approval_is_attributed(client, people):
    old_token = _login(client, "duty.guy")
    _lock(client, "duty.guy")
    rid = _file(client, _headers(old_token)).json()["id"]
    client.post(f"/api/unlock-requests/{rid}/decision", headers=people["sec1"], json={"decision": "approved"})
    client.post("/api/auth/login", json={"username": "duty.guy", "password": PASSWORD, "client_label": "first"})
    client.post("/api/auth/login", json={"username": "duty.guy", "password": PASSWORD, "client_label": "second"})
    linked = get_connection().execute(
        "SELECT COUNT(*) FROM audit_events WHERE action='auth.login' AND metadata_json LIKE ?",
        (f'%"unlock_request_id": {rid}%',),
    ).fetchone()[0]
    assert linked == 1
