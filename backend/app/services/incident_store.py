import json
from datetime import datetime, timezone

from sqlalchemy import text

from app.services.database import get_connection, init_db


def save_incident(
    source: str,
    logs: str,
    analysis: dict,
    user_id: int,
    fix_description: str | None = None,
) -> dict:
    init_db()
    created_at = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:
        result = connection.execute(
            text("""
                INSERT INTO incidents (
                    user_id, source, logs, analysis_json, fix_description,
                    verification_status, verification_notes, created_at
                )
                VALUES (
                    :user_id, :source, :logs, :analysis_json, :fix_description,
                    'not_run', '', :created_at
                )
            """),
            {
                "user_id": user_id,
                "source": source,
                "logs": logs,
                "analysis_json": json.dumps(analysis),
                "fix_description": fix_description,
                "created_at": created_at,
            },
        )
        incident_id = result.lastrowid

    incident = get_incident(incident_id, user_id)
    if incident is None:
        raise RuntimeError("Incident was saved but could not be retrieved.")
    return incident


def _row_to_dict(row) -> dict:
    result = dict(row)
    result["analysis"] = json.loads(result.pop("analysis_json"))
    return result


def get_incident(incident_id: int, user_id: int) -> dict | None:
    init_db()
    with get_connection() as connection:
        row = connection.execute(
            text("""
                SELECT * FROM incidents
                WHERE id = :incident_id AND user_id = :user_id
            """),
            {"incident_id": incident_id, "user_id": user_id},
        ).mappings().first()

    return _row_to_dict(row) if row else None


def list_incidents(
    user_id: int,
    limit: int = 20,
    offset: int = 0,
) -> list[dict]:
    init_db()
    with get_connection() as connection:
        rows = connection.execute(
            text("""
                SELECT * FROM incidents
                WHERE user_id = :user_id
                ORDER BY id DESC
                LIMIT :limit OFFSET :offset
            """),
            {"user_id": user_id, "limit": limit, "offset": offset},
        ).mappings().all()

    return [_row_to_dict(row) for row in rows]


def update_fix_description(
    incident_id: int,
    user_id: int,
    fix_description: str | None,
) -> dict | None:
    init_db()
    with get_connection() as connection:
        result = connection.execute(
            text("""
                UPDATE incidents
                SET fix_description = :fix_description
                WHERE id = :incident_id AND user_id = :user_id
            """),
            {
                "fix_description": fix_description,
                "incident_id": incident_id,
                "user_id": user_id,
            },
        )
        if result.rowcount == 0:
            return None

    return get_incident(incident_id, user_id)


def update_verification(
    incident_id: int,
    user_id: int,
    status: str,
    notes: str = "",
) -> dict | None:
    init_db()
    verified_at = (
        datetime.now(timezone.utc).isoformat()
        if status in {"passed", "failed"}
        else None
    )

    with get_connection() as connection:
        result = connection.execute(
            text("""
                UPDATE incidents
                SET verification_status = :status,
                    verification_notes = :notes,
                    verified_at = :verified_at
                WHERE id = :incident_id AND user_id = :user_id
            """),
            {
                "status": status,
                "notes": notes,
                "verified_at": verified_at,
                "incident_id": incident_id,
                "user_id": user_id,
            },
        )
        if result.rowcount == 0:
            return None

    return get_incident(incident_id, user_id)
