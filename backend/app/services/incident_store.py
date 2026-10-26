import json
import os
import sqlite3

from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "incident_memory.db"


def get_db_path() -> Path:
    return Path(os.getenv("INCIDENT_DB_PATH", str(DEFAULT_DB_PATH)))


def get_connection():
    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                logs TEXT NOT NULL,
                analysis_json TEXT NOT NULL,
                fix_description TEXT,
                verification_status TEXT NOT NULL DEFAULT 'not_run',
                verification_notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                verified_at TEXT
            )
            """
        )


def save_incident(
    source: str,
    logs: str,
    analysis: dict,
    fix_description: str | None = None,
) -> dict:
    init_db()

    created_at = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO incidents (
                source, logs, analysis_json, fix_description,
                verification_status, verification_notes, created_at
            )
            VALUES (?, ?, ?, ?, 'not_run', '', ?)
            """,
            (
                source,
                logs,
                json.dumps(analysis),
                fix_description,
                created_at,
            ),
        )
        incident_id = cursor.lastrowid

    incident = get_incident(incident_id)
    if incident is None:
        raise RuntimeError("Incident was saved but could not be retrieved.")

    return incident


def _row_to_dict(row: sqlite3.Row) -> dict:
    result = dict(row)
    result["analysis"] = json.loads(result.pop("analysis_json"))
    return result


def get_incident(incident_id: int) -> dict | None:
    init_db()

    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()

    return _row_to_dict(row) if row else None


def list_incidents(limit: int = 20, offset: int = 0) -> list[dict]:
    init_db()

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM incidents
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()

    return [_row_to_dict(row) for row in rows]



def update_fix_description(
    incident_id: int,
    fix_description: str | None,
) -> dict | None:
    init_db()

    with get_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE incidents
            SET fix_description = ?
            WHERE id = ?
            """,
            (fix_description, incident_id),
        )

        if cursor.rowcount == 0:
            return None

    return get_incident(incident_id)


def update_verification(
    incident_id: int,
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
        cursor = connection.execute(
            """
            UPDATE incidents
            SET verification_status = ?,
                verification_notes = ?,
                verified_at = ?
            WHERE id = ?
            """,
            (status, notes, verified_at, incident_id),
        )

        if cursor.rowcount == 0:
            return None

    return get_incident(incident_id)
