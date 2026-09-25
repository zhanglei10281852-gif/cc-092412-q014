from __future__ import annotations

from typing import Any

from app.repositories.base import Repository, row_dict, rows_dict


class UnlockRequestRepository(Repository):
    table = "unlock_requests"
    entity_name = "解锁申请"

    def pending_for_target(self, target_user_id: int) -> dict[str, Any] | None:
        return row_dict(self.connection.execute(
            "SELECT * FROM unlock_requests WHERE target_user_id=? AND status='pending'",
            (target_user_id,),
        ).fetchone())

    def approvals(self, request_id: int) -> list[dict]:
        return rows_dict(self.connection.execute(
            "SELECT a.*,u.username AS approver_username,u.display_name AS approver_name "
            "FROM unlock_request_approvals a JOIN users u ON u.id=a.approver_user_id "
            "WHERE a.request_id=? ORDER BY a.step",
            (request_id,),
        ).fetchall())

    def list(
        self,
        *,
        status: str | None,
        target_user_id: int | None,
        applicant_user_id: int | None,
        limit: int,
        offset: int,
    ) -> list[dict]:
        conditions: list[str] = []
        params: list[Any] = []
        for column, value in (
            ("r.status", status),
            ("r.target_user_id", target_user_id),
            ("r.applicant_user_id", applicant_user_id),
        ):
            if value is not None:
                conditions.append(f"{column}=?")
                params.append(value)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        params.extend([limit, offset])
        return rows_dict(self.connection.execute(
            "SELECT r.*,t.username AS target_username,a.username AS applicant_username "
            "FROM unlock_requests r "
            "JOIN users t ON t.id=r.target_user_id "
            "JOIN users a ON a.id=r.applicant_user_id"
            + where + " ORDER BY r.id DESC LIMIT ? OFFSET ?",
            tuple(params),
        ).fetchall())

    def pending_with_approvals(self) -> list[dict]:
        return rows_dict(self.connection.execute(
            "SELECT DISTINCT r.* FROM unlock_requests r "
            "JOIN unlock_request_approvals a ON a.request_id=r.id "
            "WHERE r.status='pending'"
        ).fetchall())

    def latest_executed_without_first_login(self, target_user_id: int) -> dict[str, Any] | None:
        return row_dict(self.connection.execute(
            "SELECT * FROM unlock_requests WHERE target_user_id=? AND status='approved' "
            "AND executed_at IS NOT NULL AND first_login_at IS NULL "
            "ORDER BY executed_at DESC LIMIT 1",
            (target_user_id,),
        ).fetchone())
