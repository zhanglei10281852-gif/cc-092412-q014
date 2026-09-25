from __future__ import annotations

import json

import pytest

from app.database import get_connection

PASSWORD = "Clerk!23456"


@pytest.fixture(autouse=True)
def fast_lock(monkeypatch):
    monkeypatch.setenv("TOWNSHIP_LOGIN_FAILURE_LIMIT", "3")


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def create_user(client, admin, username, display_name, role_codes):
    response = client.post(
        "/api/users",
        headers=admin["headers"],
        json={"username": username, "password": PASSWORD, "display_name": display_name, "role_codes": role_codes},
    )
    assert response.status_code == 201, response.text
    return response.json()


def login(client, username, password=PASSWORD):
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": password, "client_label": "tests"},
    )
    assert response.status_code == 200, response.text
    return response.json()["token"]


def lock_account(client, username, attempts=8):
    for _ in range(attempts):
        response = client.post(
            "/api/auth/login",
            json={"username": username, "password": "Wrong!23456", "client_label": "tests"},
        )
        if response.status_code == 401 and response.json()["error"]["code"] == "account_locked":
            return
    raise AssertionError(f"账号 {username} 未被锁定")


def make_request(client, applicant_token, target_username, **overrides):
    payload = {"target_username": target_username, "reason": "节假日值班急需处理业务", "valid_minutes": 60, "session_scope": "all"}
    payload.update(overrides)
    response = client.post("/api/unlock-requests", headers=auth_headers(applicant_token), json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def audit_events(client, admin, **params):
    response = client.get("/api/audit", headers=admin["headers"], params=params)
    assert response.status_code == 200, response.text
    return response.json()["data"]


@pytest.fixture()
def officers(client, admin):
    applicant = create_user(client, admin, "duty.clerk", "值班人员", ["clerk"])
    first = create_user(client, admin, "sec.one", "安全员甲", ["security_officer"])
    second = create_user(client, admin, "sec.two", "安全员乙", ["security_officer"])
    return {
        "applicant": applicant,
        "first": first,
        "second": second,
        "applicant_token": login(client, "duty.clerk"),
        "first_token": login(client, "sec.one"),
        "second_token": login(client, "sec.two"),
    }


def test_unlock_happy_path_restores_login_and_revokes_sessions(client, admin, officers):
    target = create_user(client, admin, "locked.user", "被锁人员", ["clerk"])
    old_token = login(client, "locked.user")
    lock_account(client, "locked.user")
    assert client.get("/api/auth/me", headers=auth_headers(old_token)).status_code == 401

    created = make_request(client, officers["applicant_token"], "locked.user")
    assert created["status"] == "pending"
    assert created["requires_second"] is False
    assert created["target_failed_count"] == 3
    assert created["correlation_id"] == f"unlock-request:{created['id']}"

    decided = client.post(
        f"/api/unlock-requests/{created['id']}/approvals",
        headers=auth_headers(officers["first_token"]),
        json={"decision": "approve"},
    )
    assert decided.status_code == 200, decided.text
    body = decided.json()
    assert body["status"] == "approved"
    assert body["executed_at"] is not None
    assert body["revoked_session_count"] == 1
    assert len(body["approvals"]) == 1

    # 终态唯一：已批准的申请不能再被决定或撤回
    for response in (
        client.post(
            f"/api/unlock-requests/{created['id']}/approvals",
            headers=auth_headers(officers["second_token"]),
            json={"decision": "reject", "note": "重复处理"},
        ),
        client.post(f"/api/unlock-requests/{created['id']}/withdraw", headers=auth_headers(officers["applicant_token"])),
    ):
        assert response.status_code == 409, response.text

    # 旧会话已失效，密码未被修改，锁定被清除
    assert client.get("/api/auth/me", headers=auth_headers(old_token)).status_code == 401
    new_token = login(client, "locked.user")
    assert client.get("/api/auth/me", headers=auth_headers(new_token)).status_code == 200
    detail = client.get(f"/api/users/{target['id']}", headers=admin["headers"]).json()
    assert detail["status"] == "active"
    assert detail["failed_login_count"] == 0
    assert detail["locked_until"] is None

    # 首次登录回写到申请，审计可对照
    final = client.get(f"/api/unlock-requests/{created['id']}", headers=admin["headers"]).json()
    assert final["first_login_at"] is not None
    assert final["first_login_session_id"] is not None

    correlation = f"unlock-request:{created['id']}"
    request_events = audit_events(client, admin, resource_type="unlock_request")
    actions = {event["action"] for event in request_events}
    assert {"unlock_request.create", "unlock_request.approve", "unlock_request.execute"} <= actions
    assert all(event["correlation_id"] == correlation for event in request_events)

    denied = audit_events(client, admin, action="auth.login", outcome="denied")
    assert any(event["actor_user_id"] == target["id"] for event in denied)

    logins = audit_events(client, admin, action="auth.login", outcome="success")
    first_login = [event for event in logins if event["correlation_id"] == correlation]
    assert len(first_login) == 1
    metadata = json.loads(first_login[0]["metadata_json"])
    assert metadata["unlock_request_id"] == created["id"]
    assert metadata["first_login_after_unlock"] is True


def test_create_request_requires_locked_target(client, admin, officers):
    create_user(client, admin, "not.locked", "未锁人员", ["clerk"])
    response = client.post(
        "/api/unlock-requests",
        headers=auth_headers(officers["applicant_token"]),
        json={"target_username": "not.locked", "reason": "测试", "valid_minutes": 30, "session_scope": "all"},
    )
    assert response.status_code == 409
    missing = client.post(
        "/api/unlock-requests",
        headers=auth_headers(officers["applicant_token"]),
        json={"target_username": "no.such", "reason": "测试", "valid_minutes": 30, "session_scope": "all"},
    )
    assert missing.status_code == 404


def test_duplicate_pending_request_rejected(client, admin, officers):
    create_user(client, admin, "dup.locked", "重复申请", ["clerk"])
    lock_account(client, "dup.locked")
    make_request(client, officers["applicant_token"], "dup.locked")
    response = client.post(
        "/api/unlock-requests",
        headers=auth_headers(officers["applicant_token"]),
        json={"target_username": "dup.locked", "reason": "重复提交", "valid_minutes": 30, "session_scope": "all"},
    )
    assert response.status_code == 409


def test_applicant_cannot_approve_own_request(client, admin):
    create_user(client, admin, "self.applicant", "自审人员", ["clerk", "security_officer"])
    create_user(client, admin, "self.locked", "被锁人员", ["clerk"])
    lock_account(client, "self.locked")
    token = login(client, "self.applicant")
    created = make_request(client, token, "self.locked")
    response = client.post(
        f"/api/unlock-requests/{created['id']}/approvals",
        headers=auth_headers(token),
        json={"decision": "approve"},
    )
    assert response.status_code == 403


def test_high_privilege_account_requires_second_approver(client, admin, officers):
    role = client.post(
        "/api/roles",
        headers=admin["headers"],
        json={"code": "useradmin", "name": "用户管理员", "permission_codes": ["users.write"]},
    )
    assert role.status_code == 201
    create_user(client, admin, "power.user", "高权限人员", ["useradmin"])
    lock_account(client, "power.user")

    created = make_request(client, officers["applicant_token"], "power.user")
    assert created["requires_second"] is True

    first = client.post(
        f"/api/unlock-requests/{created['id']}/approvals",
        headers=auth_headers(officers["first_token"]),
        json={"decision": "approve"},
    )
    assert first.status_code == 200
    assert first.json()["status"] == "pending"

    duplicate = client.post(
        f"/api/unlock-requests/{created['id']}/approvals",
        headers=auth_headers(officers["first_token"]),
        json={"decision": "approve"},
    )
    assert duplicate.status_code == 409

    second = client.post(
        f"/api/unlock-requests/{created['id']}/approvals",
        headers=auth_headers(officers["second_token"]),
        json={"decision": "approve"},
    )
    assert second.status_code == 200
    assert second.json()["status"] == "approved"
    assert [item["step"] for item in second.json()["approvals"]] == [1, 2]
    login(client, "power.user")


def test_reject_is_terminal_and_requires_note(client, admin, officers):
    create_user(client, admin, "reject.me", "被拒人员", ["clerk"])
    lock_account(client, "reject.me")
    created = make_request(client, officers["applicant_token"], "reject.me")

    missing_note = client.post(
        f"/api/unlock-requests/{created['id']}/approvals",
        headers=auth_headers(officers["first_token"]),
        json={"decision": "reject"},
    )
    assert missing_note.status_code == 422

    rejected = client.post(
        f"/api/unlock-requests/{created['id']}/approvals",
        headers=auth_headers(officers["first_token"]),
        json={"decision": "reject", "note": "原因不充分"},
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"

    late = client.post(
        f"/api/unlock-requests/{created['id']}/approvals",
        headers=auth_headers(officers["second_token"]),
        json={"decision": "approve"},
    )
    assert late.status_code == 409


def test_withdraw_only_by_applicant(client, admin, officers):
    create_user(client, admin, "withdraw.me", "撤回人员", ["clerk"])
    lock_account(client, "withdraw.me")
    created = make_request(client, officers["applicant_token"], "withdraw.me")

    forbidden = client.post(
        f"/api/unlock-requests/{created['id']}/withdraw",
        headers=auth_headers(officers["first_token"]),
    )
    assert forbidden.status_code == 403

    withdrawn = client.post(
        f"/api/unlock-requests/{created['id']}/withdraw",
        headers=auth_headers(officers["applicant_token"]),
    )
    assert withdrawn.status_code == 200
    assert withdrawn.json()["status"] == "withdrawn"

    decided = client.post(
        f"/api/unlock-requests/{created['id']}/approvals",
        headers=auth_headers(officers["first_token"]),
        json={"decision": "approve"},
    )
    assert decided.status_code == 409


def test_expired_request_is_terminal(client, admin, officers):
    create_user(client, admin, "expire.me", "过期人员", ["clerk"])
    lock_account(client, "expire.me")
    created = make_request(client, officers["applicant_token"], "expire.me", valid_minutes=1)
    get_connection().execute(
        "UPDATE unlock_requests SET expires_at='2020-01-01T00:00:00+00:00' WHERE id=?",
        (created["id"],),
    )
    detail = client.get(f"/api/unlock-requests/{created['id']}", headers=admin["headers"])
    assert detail.status_code == 200
    assert detail.json()["status"] == "expired"

    decided = client.post(
        f"/api/unlock-requests/{created['id']}/approvals",
        headers=auth_headers(officers["first_token"]),
        json={"decision": "approve"},
    )
    assert decided.status_code == 409

    events = audit_events(client, admin, action="unlock_request.expire")
    assert len(events) == 1
    assert events[0]["actor_name"] == "system"


def test_approver_permission_lapse_terminates_request(client, admin, officers):
    role = client.post(
        "/api/roles",
        headers=admin["headers"],
        json={"code": "power.role", "name": "高权限角色", "permission_codes": ["roles.write"]},
    )
    assert role.status_code == 201
    create_user(client, admin, "lapse.target", "高权限目标", ["power.role"])
    lock_account(client, "lapse.target")
    created = make_request(client, officers["applicant_token"], "lapse.target")
    assert created["requires_second"] is True

    first = client.post(
        f"/api/unlock-requests/{created['id']}/approvals",
        headers=auth_headers(officers["first_token"]),
        json={"decision": "approve"},
    )
    assert first.json()["status"] == "pending"

    # 第一名审批人的审批权限在完成前被收回，申请被终止
    replaced = client.put(
        f"/api/users/{officers['first']['id']}/roles",
        headers=admin["headers"],
        json={"role_codes": ["clerk"]},
    )
    assert replaced.status_code == 200

    detail = client.get(f"/api/unlock-requests/{created['id']}", headers=admin["headers"]).json()
    assert detail["status"] == "terminated"
    assert "审批人权限" in detail["decision_note"]

    late = client.post(
        f"/api/unlock-requests/{created['id']}/approvals",
        headers=auth_headers(officers["second_token"]),
        json={"decision": "approve"},
    )
    assert late.status_code == 409

    events = audit_events(client, admin, action="unlock_request.terminate")
    assert len(events) == 1
    metadata = json.loads(events[0]["metadata_json"])
    assert metadata["lapsed_approver_user_ids"] == [officers["first"]["id"]]


def test_approver_account_disabled_terminates_request(client, admin, officers):
    role = client.post(
        "/api/roles",
        headers=admin["headers"],
        json={"code": "power.two", "name": "高权限角色二", "permission_codes": ["users.write"]},
    )
    assert role.status_code == 201
    create_user(client, admin, "disable.target", "高权限目标二", ["power.two"])
    lock_account(client, "disable.target")
    created = make_request(client, officers["applicant_token"], "disable.target")
    client.post(
        f"/api/unlock-requests/{created['id']}/approvals",
        headers=auth_headers(officers["first_token"]),
        json={"decision": "approve"},
    )
    disabled = client.patch(
        f"/api/users/{officers['first']['id']}",
        headers=admin["headers"],
        json={"status": "disabled"},
    )
    assert disabled.status_code == 200
    detail = client.get(f"/api/unlock-requests/{created['id']}", headers=admin["headers"]).json()
    assert detail["status"] == "terminated"


def test_lock_snapshot_mismatch_blocks_execution(client, admin, officers):
    create_user(client, admin, "mismatch.user", "锁变人员", ["clerk"])
    lock_account(client, "mismatch.user")
    created = make_request(client, officers["applicant_token"], "mismatch.user")
    get_connection().execute(
        "UPDATE users SET locked_until='2099-01-01T00:00:00+00:00' WHERE username='mismatch.user'"
    )
    decided = client.post(
        f"/api/unlock-requests/{created['id']}/approvals",
        headers=auth_headers(officers["first_token"]),
        json={"decision": "approve"},
    )
    assert decided.status_code == 409
    detail = client.get(f"/api/unlock-requests/{created['id']}", headers=admin["headers"]).json()
    assert detail["status"] == "pending"
    assert detail["approvals"] == []


def test_session_scope_none_keeps_sessions(client, admin, officers):
    create_user(client, admin, "scope.none", "保留会话", ["clerk"])
    old_token = login(client, "scope.none")
    lock_account(client, "scope.none")
    created = make_request(client, officers["applicant_token"], "scope.none", session_scope="none")
    decided = client.post(
        f"/api/unlock-requests/{created['id']}/approvals",
        headers=auth_headers(officers["first_token"]),
        json={"decision": "approve"},
    )
    assert decided.json()["revoked_session_count"] == 0
    assert client.get("/api/auth/me", headers=auth_headers(old_token)).status_code == 200


def test_session_scope_pre_lock_revokes_old_sessions(client, admin, officers):
    create_user(client, admin, "scope.pre", "锁定前会话", ["clerk"])
    old_token = login(client, "scope.pre")
    lock_account(client, "scope.pre")
    created = make_request(client, officers["applicant_token"], "scope.pre", session_scope="pre_lock")
    decided = client.post(
        f"/api/unlock-requests/{created['id']}/approvals",
        headers=auth_headers(officers["first_token"]),
        json={"decision": "approve"},
    )
    assert decided.json()["revoked_session_count"] == 1
    assert client.get("/api/auth/me", headers=auth_headers(old_token)).status_code == 401
    login(client, "scope.pre")


def test_disabled_account_is_not_reactivated(client, admin, officers):
    target = create_user(client, admin, "stays.disabled", "停用人员", ["clerk"])
    lock_account(client, "stays.disabled")
    created = make_request(client, officers["applicant_token"], "stays.disabled")
    changed = client.patch(f"/api/users/{target['id']}", headers=admin["headers"], json={"status": "disabled"})
    assert changed.status_code == 200

    decided = client.post(
        f"/api/unlock-requests/{created['id']}/approvals",
        headers=auth_headers(officers["first_token"]),
        json={"decision": "approve"},
    )
    assert decided.status_code == 200
    assert decided.json()["status"] == "approved"

    detail = client.get(f"/api/users/{target['id']}", headers=admin["headers"]).json()
    assert detail["status"] == "disabled"
    assert detail["locked_until"] is None
    assert detail["failed_login_count"] == 0
    login_attempt = client.post(
        "/api/auth/login",
        json={"username": "stays.disabled", "password": PASSWORD, "client_label": "tests"},
    )
    assert login_attempt.status_code == 401


def test_unlock_permissions_are_enforced(client, admin):
    create_user(client, admin, "no.perms", "无权限人员", [])
    create_user(client, admin, "perm.target", "权限目标", ["clerk"])
    lock_account(client, "perm.target")
    token = login(client, "no.perms")
    created = client.post(
        "/api/unlock-requests",
        headers=auth_headers(token),
        json={"target_username": "perm.target", "reason": "测试", "valid_minutes": 30, "session_scope": "all"},
    )
    assert created.status_code == 403
    assert client.get("/api/unlock-requests", headers=auth_headers(token)).status_code == 403

    request_only = create_user(client, admin, "request.only", "仅申请", ["clerk"])
    request_only_token = login(client, "request.only")
    made = make_request(client, request_only_token, "perm.target")
    decide = client.post(
        f"/api/unlock-requests/{made['id']}/approvals",
        headers=auth_headers(request_only_token),
        json={"decision": "approve"},
    )
    assert decide.status_code == 403
    assert request_only["username"] == "request.only"


def test_auditor_role_can_read_requests(client, admin, officers):
    auditor = create_user(client, admin, "audit.viewer", "审计员", ["auditor"])
    create_user(client, admin, "audit.target", "被锁目标", ["clerk"])
    lock_account(client, "audit.target")
    make_request(client, officers["applicant_token"], "audit.target")
    token = login(client, "audit.viewer")
    listing = client.get("/api/unlock-requests", headers=auth_headers(token))
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    detail = client.get(f"/api/unlock-requests/{listing.json()['data'][0]['id']}", headers=auth_headers(token))
    assert detail.status_code == 200
    assert auditor["username"] == "audit.viewer"


def test_applicant_can_track_own_request(client, admin, officers):
    create_user(client, admin, "track.me", "跟踪人员", ["clerk"])
    lock_account(client, "track.me")
    created = make_request(client, officers["applicant_token"], "track.me")
    detail = client.get(f"/api/unlock-requests/{created['id']}", headers=auth_headers(officers["applicant_token"]))
    assert detail.status_code == 200
    assert detail.json()["id"] == created["id"]

    create_user(client, admin, "other.clerk", "无关人员", ["clerk"])
    other_token = login(client, "other.clerk")
    forbidden = client.get(f"/api/unlock-requests/{created['id']}", headers=auth_headers(other_token))
    assert forbidden.status_code == 403


def test_blank_reason_is_rejected(client, admin, officers):
    create_user(client, admin, "blank.reason", "空原因", ["clerk"])
    lock_account(client, "blank.reason")
    response = client.post(
        "/api/unlock-requests",
        headers=auth_headers(officers["applicant_token"]),
        json={"target_username": "blank.reason", "reason": "   ", "valid_minutes": 30, "session_scope": "all"},
    )
    assert response.status_code == 422
