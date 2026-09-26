"""
SQLite database manager using aiosqlite.
Single connection pool, all operations async.
"""
from __future__ import annotations
import asyncio
import json
import aiosqlite
from pathlib import Path
import datetime as _dt
from datetime import datetime
from typing import Optional, Any
from loki.models.schema import (
    Project, Target, Session, Endpoint, Request, Finding, Evidence, AuthState
)

DB_PATH = Path.home() / ".loki" / "loki.db"


class Database:
    """Async SQLite database manager. Use as async context manager or call init() once."""

    _instance: Optional["Database"] = None
    _conn: Optional[aiosqlite.Connection] = None

    def __init__(self, path: Path = DB_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    async def init(self) -> None:
        """Open connection and create all tables."""
        self._conn = await aiosqlite.connect(str(self.path))
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._create_tables()
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    async def _create_tables(self) -> None:
        await self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS projects (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL UNIQUE,
                description TEXT DEFAULT '',
                created_at  TEXT NOT NULL,
                active      INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS targets (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                domain      TEXT NOT NULL,
                scope_type  TEXT DEFAULT 'in_scope',
                notes       TEXT DEFAULT '',
                created_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id       INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                target_domain    TEXT NOT NULL,
                email            TEXT DEFAULT '',
                cookies          TEXT DEFAULT '[]',
                local_storage    TEXT DEFAULT '{}',
                session_storage  TEXT DEFAULT '{}',
                auth_headers     TEXT DEFAULT '{}',
                auth_state       TEXT DEFAULT 'idle',
                created_at       TEXT NOT NULL,
                updated_at       TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS endpoints (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id    INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                target_domain TEXT NOT NULL,
                method        TEXT NOT NULL,
                path          TEXT NOT NULL,
                path_pattern  TEXT NOT NULL,
                first_seen    TEXT NOT NULL,
                last_seen     TEXT NOT NULL,
                hit_count     INTEGER DEFAULT 1,
                tags          TEXT DEFAULT '[]',
                UNIQUE(project_id, method, path)
            );

            CREATE TABLE IF NOT EXISTS requests (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id       INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                endpoint_id      INTEGER REFERENCES endpoints(id),
                method           TEXT NOT NULL,
                url              TEXT NOT NULL,
                request_headers  TEXT DEFAULT '{}',
                request_body     TEXT DEFAULT '',
                response_status  INTEGER DEFAULT 0,
                response_headers TEXT DEFAULT '{}',
                response_body    TEXT DEFAULT '',
                response_time_ms INTEGER DEFAULT 0,
                captured_at      TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                title           TEXT NOT NULL,
                severity        TEXT DEFAULT 'info',
                category        TEXT DEFAULT '',
                description     TEXT DEFAULT '',
                request_id      INTEGER REFERENCES requests(id),
                evidence_paths  TEXT DEFAULT '[]',
                cvss_score      REAL DEFAULT 0.0,
                status          TEXT DEFAULT 'open',
                created_at      TEXT NOT NULL,
                notes           TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id    INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
                evidence_type TEXT NOT NULL,
                file_path     TEXT DEFAULT '',
                content       TEXT DEFAULT '',
                captured_at   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS active_project (
                id         INTEGER PRIMARY KEY CHECK (id = 1),
                project_id INTEGER REFERENCES projects(id)
            );
        """)

    # ─── Project operations ───────────────────────────────────────────────

    async def create_project(self, name: str, description: str = "") -> Project:
        now = datetime.now(_dt.timezone.utc).replace(tzinfo=None).isoformat()
        async with self._conn.execute(
            "INSERT INTO projects (name, description, created_at) VALUES (?, ?, ?)",
            (name, description, now)
        ) as cur:
            project_id = cur.lastrowid
        await self._conn.commit()
        return Project(id=project_id, name=name, description=description)

    async def get_project(self, name: str) -> Optional[Project]:
        async with self._conn.execute(
            "SELECT * FROM projects WHERE name = ?", (name,)
        ) as cur:
            row = await cur.fetchone()
            if row:
                return Project(**dict(row))
        return None

    async def list_projects(self) -> list[Project]:
        async with self._conn.execute("SELECT * FROM projects ORDER BY created_at DESC") as cur:
            rows = await cur.fetchall()
            return [Project(**dict(r)) for r in rows]

    async def set_active_project(self, project_id: int) -> None:
        await self._conn.execute(
            "INSERT OR REPLACE INTO active_project (id, project_id) VALUES (1, ?)",
            (project_id,)
        )
        await self._conn.commit()

    async def get_active_project(self) -> Optional[Project]:
        async with self._conn.execute(
            "SELECT p.* FROM projects p JOIN active_project a ON p.id = a.project_id"
        ) as cur:
            row = await cur.fetchone()
            if row:
                return Project(**dict(row))
        return None

    # ─── Target operations ───────────────────────────────────────────────

    async def add_target(self, project_id: int, domain: str, scope_type: str = "in_scope") -> Target:
        now = datetime.now(_dt.timezone.utc).replace(tzinfo=None).isoformat()
        async with self._conn.execute(
            "INSERT OR IGNORE INTO targets (project_id, domain, scope_type, created_at) VALUES (?, ?, ?, ?)",
            (project_id, domain, scope_type, now)
        ) as cur:
            target_id = cur.lastrowid
        await self._conn.commit()
        return Target(id=target_id, project_id=project_id, domain=domain, scope_type=scope_type)

    async def get_targets(self, project_id: int) -> list[Target]:
        async with self._conn.execute(
            "SELECT * FROM targets WHERE project_id = ?", (project_id,)
        ) as cur:
            rows = await cur.fetchall()
            return [Target(**dict(r)) for r in rows]

    async def is_in_scope(self, project_id: int, domain: str) -> bool:
        """Check if domain matches any in-scope target (supports wildcards like *.example.com)."""
        targets = await self.get_targets(project_id)
        for t in targets:
            if t.scope_type == "out_of_scope":
                continue
            if t.domain.startswith("*."):
                base = t.domain[2:]
                if domain == base or domain.endswith("." + base):
                    return True
            elif t.domain == domain:
                return True
        return False

    # ─── Session operations ──────────────────────────────────────────────

    async def upsert_session(self, session: Session) -> Session:
        now = datetime.now(_dt.timezone.utc).replace(tzinfo=None).isoformat()
        session.updated_at = datetime.now(_dt.timezone.utc).replace(tzinfo=None)
        if session.id == 0:
            session.created_at = datetime.now(_dt.timezone.utc).replace(tzinfo=None)
            async with self._conn.execute(
                """INSERT INTO sessions
                   (project_id, target_domain, email, cookies, local_storage,
                    session_storage, auth_headers, auth_state, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (session.project_id, session.target_domain, session.email,
                 session.cookies, session.local_storage, session.session_storage,
                 session.auth_headers, session.auth_state.value,
                 session.created_at.isoformat(), now)
            ) as cur:
                session.id = cur.lastrowid
        else:
            await self._conn.execute(
                """UPDATE sessions SET
                   email=?, cookies=?, local_storage=?, session_storage=?,
                   auth_headers=?, auth_state=?, updated_at=?
                   WHERE id=?""",
                (session.email, session.cookies, session.local_storage,
                 session.session_storage, session.auth_headers,
                 session.auth_state.value, now, session.id)
            )
        await self._conn.commit()
        return session

    async def get_session(self, project_id: int, target_domain: str) -> Optional[Session]:
        async with self._conn.execute(
            "SELECT * FROM sessions WHERE project_id=? AND target_domain=? ORDER BY updated_at DESC LIMIT 1",
            (project_id, target_domain)
        ) as cur:
            row = await cur.fetchone()
            if row:
                d = dict(row)
                d["auth_state"] = AuthState(d["auth_state"])
                return Session(**d)
        return None

    # ─── Endpoint operations ─────────────────────────────────────────────

    async def upsert_endpoint(self, ep: Endpoint) -> Endpoint:
        now = datetime.now(_dt.timezone.utc).replace(tzinfo=None).isoformat()
        async with self._conn.execute(
            """INSERT INTO endpoints
               (project_id, target_domain, method, path, path_pattern, first_seen, last_seen, hit_count, tags)
               VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
               ON CONFLICT(project_id, method, path) DO UPDATE SET
               last_seen=excluded.last_seen,
               hit_count=hit_count+1""",
            (ep.project_id, ep.target_domain, ep.method, ep.path,
             ep.path_pattern, now, now, ep.tags)
        ) as cur:
            ep.id = cur.lastrowid or ep.id
        await self._conn.commit()
        return ep

    async def get_endpoints(self, project_id: int, domain: Optional[str] = None) -> list[Endpoint]:
        if domain:
            async with self._conn.execute(
                "SELECT * FROM endpoints WHERE project_id=? AND target_domain=? ORDER BY method, path",
                (project_id, domain)
            ) as cur:
                rows = await cur.fetchall()
        else:
            async with self._conn.execute(
                "SELECT * FROM endpoints WHERE project_id=? ORDER BY method, path",
                (project_id,)
            ) as cur:
                rows = await cur.fetchall()
        return [Endpoint(**dict(r)) for r in rows]

    # ─── Request operations ──────────────────────────────────────────────

    async def save_request(self, req: Request) -> Request:
        now = datetime.now(_dt.timezone.utc).replace(tzinfo=None).isoformat()
        async with self._conn.execute(
            """INSERT INTO requests
               (project_id, endpoint_id, method, url, request_headers, request_body,
                response_status, response_headers, response_body, response_time_ms, captured_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (req.project_id, req.endpoint_id, req.method, req.url,
             req.request_headers, req.request_body, req.response_status,
             req.response_headers, req.response_body, req.response_time_ms, now)
        ) as cur:
            req.id = cur.lastrowid
        await self._conn.commit()
        return req

    async def get_requests(self, project_id: int, limit: int = 100) -> list[Request]:
        async with self._conn.execute(
            "SELECT * FROM requests WHERE project_id=? ORDER BY captured_at DESC LIMIT ?",
            (project_id, limit)
        ) as cur:
            rows = await cur.fetchall()
            return [Request(**dict(r)) for r in rows]

    # ─── Finding operations ──────────────────────────────────────────────

    async def create_finding(self, finding: Finding) -> Finding:
        now = datetime.now(_dt.timezone.utc).replace(tzinfo=None).isoformat()
        request_id = finding.request_id if finding.request_id else None
        async with self._conn.execute(
            """INSERT INTO findings
               (project_id, title, severity, category, description, request_id,
                evidence_paths, cvss_score, status, created_at, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (finding.project_id, finding.title, finding.severity, finding.category,
             finding.description, request_id, finding.evidence_paths,
             finding.cvss_score, finding.status, now, finding.notes)
        ) as cur:
            finding.id = cur.lastrowid
        await self._conn.commit()
        return finding

    async def list_findings(self, project_id: int) -> list[Finding]:
        async with self._conn.execute(
            "SELECT * FROM findings WHERE project_id=? ORDER BY severity, created_at DESC",
            (project_id,)
        ) as cur:
            rows = await cur.fetchall()
            return [Finding(**dict(r)) for r in rows]

    async def get_finding(self, finding_id: int) -> Optional[Finding]:
        async with self._conn.execute(
            "SELECT * FROM findings WHERE id=?", (finding_id,)
        ) as cur:
            row = await cur.fetchone()
            if row:
                return Finding(**dict(row))
        return None