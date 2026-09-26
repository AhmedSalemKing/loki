"""
SQLite storage manager via aiosqlite.
Single file per project: ~/.loki/projects/<name>/loki.db
"""
from __future__ import annotations
import json
import os
import stat
from pathlib import Path
from typing import Any, Optional
import aiosqlite
from .models import (
    Project, Target, BrowserSession, CapturedRequest, Endpoint, Finding
)

LOKI_DIR = Path.home() / ".loki"


def _project_dir(project_name: str) -> Path:
    d = LOKI_DIR / "projects" / project_name
    d.mkdir(parents=True, exist_ok=True)
    return d


def _db_path(project_name: str) -> Path:
    return _project_dir(project_name) / "loki.db"


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    created_at TEXT,
    active INTEGER DEFAULT 1,
    notes TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    host TEXT NOT NULL,
    base_url TEXT NOT NULL,
    scope TEXT DEFAULT '[]',
    excluded TEXT DEFAULT '[]',
    tech_stack TEXT DEFAULT '[]',
    added_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    host TEXT NOT NULL,
    email TEXT,
    authenticated INTEGER DEFAULT 0,
    cookies TEXT DEFAULT '[]',
    local_storage TEXT DEFAULT '{}',
    session_storage TEXT DEFAULT '{}',
    tokens TEXT DEFAULT '[]',
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    host TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    path TEXT NOT NULL,
    query TEXT DEFAULT '',
    request_headers TEXT DEFAULT '{}',
    request_body TEXT,
    status INTEGER,
    response_headers TEXT DEFAULT '{}',
    response_body TEXT,
    response_size INTEGER DEFAULT 0,
    page_url TEXT,
    captured_at TEXT
);

CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    host TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    path TEXT NOT NULL,
    classification TEXT DEFAULT 'unknown',
    risk TEXT DEFAULT 'none',
    signals TEXT DEFAULT '[]',
    observed_count INTEGER DEFAULT 1,
    status_codes TEXT DEFAULT '[]',
    response_sizes TEXT DEFAULT '[]',
    first_seen TEXT,
    last_seen TEXT,
    request_ids TEXT DEFAULT '[]',
    notes TEXT DEFAULT '',
    UNIQUE(project_id, method, url)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    status TEXT DEFAULT 'candidate',
    risk TEXT DEFAULT 'medium',
    signals TEXT DEFAULT '[]',
    confidence REAL DEFAULT 0.0,
    evidence TEXT DEFAULT '[]',
    created_at TEXT
);
"""


class StorageManager:
    def __init__(self, project_name: str):
        self.project_name = project_name
        self.db_path = _db_path(project_name)
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(SCHEMA)
        await self._conn.commit()
        # Secure permissions
        os.chmod(self.db_path, stat.S_IRUSR | stat.S_IWUSR)

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *_):
        await self.close()

    # ── helpers ──────────────────────────────────────────────────────────────

    def _j(self, v: Any) -> str:
        return json.dumps(v, default=str)

    def _row_to_dict(self, row) -> dict:
        return dict(row) if row else {}

    # ── Project ───────────────────────────────────────────────────────────────

    async def save_project(self, p: Project) -> None:
        await self._conn.execute(
            "INSERT OR REPLACE INTO projects VALUES (?,?,?,?,?)",
            (p.id, p.name, str(p.created_at), int(p.active), p.notes)
        )
        await self._conn.commit()

    async def get_project(self, name: str) -> Optional[Project]:
        async with self._conn.execute(
            "SELECT * FROM projects WHERE name=?", (name,)
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        d = self._row_to_dict(row)
        return Project(**d)

    async def list_projects(self) -> list[Project]:
        async with self._conn.execute("SELECT * FROM projects ORDER BY created_at DESC") as cur:
            rows = await cur.fetchall()
        return [Project(**self._row_to_dict(r)) for r in rows]

    # ── Target ────────────────────────────────────────────────────────────────

    async def save_target(self, t: Target) -> None:
        await self._conn.execute(
            "INSERT OR REPLACE INTO targets VALUES (?,?,?,?,?,?,?,?)",
            (t.id, t.project_id, t.host, t.base_url,
             self._j(t.scope), self._j(t.excluded), self._j(t.tech_stack), str(t.added_at))
        )
        await self._conn.commit()

    async def get_target(self, project_id: str) -> Optional[Target]:
        async with self._conn.execute(
            "SELECT * FROM targets WHERE project_id=? ORDER BY added_at DESC LIMIT 1",
            (project_id,)
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        d = self._row_to_dict(row)
        d["scope"] = json.loads(d["scope"])
        d["excluded"] = json.loads(d["excluded"])
        d["tech_stack"] = json.loads(d["tech_stack"])
        return Target(**d)

    # ── Session ───────────────────────────────────────────────────────────────

    async def save_session(self, s: BrowserSession) -> None:
        await self._conn.execute(
            "INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (s.id, s.project_id, s.host, s.email, int(s.authenticated),
             self._j([c for c in s.cookies]),
             self._j(s.local_storage), self._j(s.session_storage),
             self._j([t.model_dump() for t in s.tokens]),
             str(s.created_at), str(s.updated_at))
        )
        await self._conn.commit()
        # Secure session file
        os.chmod(self.db_path, stat.S_IRUSR | stat.S_IWUSR)

    async def get_session(self, project_id: str, host: str) -> Optional[BrowserSession]:
        async with self._conn.execute(
            "SELECT * FROM sessions WHERE project_id=? AND host=? ORDER BY updated_at DESC LIMIT 1",
            (project_id, host)
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        from .models import SessionToken
        d = self._row_to_dict(row)
        d["authenticated"] = bool(d["authenticated"])
        d["cookies"] = json.loads(d["cookies"])
        d["local_storage"] = json.loads(d["local_storage"])
        d["session_storage"] = json.loads(d["session_storage"])
        raw_tokens = json.loads(d["tokens"])
        d["tokens"] = [SessionToken(**t) for t in raw_tokens]
        return BrowserSession(**d)

    # ── Requests ──────────────────────────────────────────────────────────────

    async def save_request(self, r: CapturedRequest) -> str:
        await self._conn.execute(
            """INSERT OR IGNORE INTO requests
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (r.id, r.project_id, r.host, r.method, r.url, r.path, r.query,
             self._j(r.request_headers), r.request_body,
             r.status, self._j(r.response_headers), r.response_body,
             r.response_size, r.page_url, str(r.captured_at))
        )
        await self._conn.commit()
        return r.id

    async def get_request(self, req_id: str) -> Optional[CapturedRequest]:
        async with self._conn.execute("SELECT * FROM requests WHERE id=?", (req_id,)) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        d = self._row_to_dict(row)
        d["request_headers"] = json.loads(d["request_headers"])
        d["response_headers"] = json.loads(d["response_headers"])
        return CapturedRequest(**d)

    async def list_requests(self, project_id: str, host: str = None, limit: int = 200) -> list[CapturedRequest]:
        if host:
            q = "SELECT * FROM requests WHERE project_id=? AND host=? ORDER BY captured_at DESC LIMIT ?"
            args = (project_id, host, limit)
        else:
            q = "SELECT * FROM requests WHERE project_id=? ORDER BY captured_at DESC LIMIT ?"
            args = (project_id, limit)
        async with self._conn.execute(q, args) as cur:
            rows = await cur.fetchall()
        result = []
        for row in rows:
            d = self._row_to_dict(row)
            d["request_headers"] = json.loads(d["request_headers"])
            d["response_headers"] = json.loads(d["response_headers"])
            result.append(CapturedRequest(**d))
        return result

    # ── Endpoints ─────────────────────────────────────────────────────────────

    async def upsert_endpoint(self, e: Endpoint) -> Endpoint:
        """Insert or merge endpoint; dedup by (project_id, method, url)."""
        async with self._conn.execute(
            "SELECT * FROM endpoints WHERE project_id=? AND method=? AND url=?",
            (e.project_id, e.method, e.url)
        ) as cur:
            existing = await cur.fetchone()

        if existing:
            d = self._row_to_dict(existing)
            codes = json.loads(d["status_codes"])
            sizes = json.loads(d["response_sizes"])
            rids  = json.loads(d["request_ids"])
            if e.status_codes:
                codes.extend(e.status_codes)
            if e.response_sizes:
                sizes.extend(e.response_sizes)
            if e.request_ids:
                rids.extend(e.request_ids)
            # Upgrade classification/risk if better
            new_class = e.classification.value
            new_risk  = e.risk.value
            old_class = d["classification"]
            old_risk  = d["risk"]
            risk_order = {"high":3,"medium":2,"low":1,"info":0,"none":-1}
            if risk_order.get(new_risk, -1) > risk_order.get(old_risk, -1):
                old_risk = new_risk
            if old_class == "unknown" and new_class != "unknown":
                old_class = new_class
            signals = list(set(json.loads(d["signals"]) + e.signals))
            await self._conn.execute(
                """UPDATE endpoints SET
                   observed_count=?, status_codes=?, response_sizes=?,
                   request_ids=?, classification=?, risk=?, signals=?, last_seen=?
                   WHERE project_id=? AND method=? AND url=?""",
                (d["observed_count"] + 1, self._j(codes[-50:]), self._j(sizes[-50:]),
                 self._j(rids[-100:]), old_class, old_risk, self._j(signals),
                 str(e.last_seen), e.project_id, e.method, e.url)
            )
            await self._conn.commit()
            e.id = d["id"]
        else:
            await self._conn.execute(
                """INSERT INTO endpoints VALUES
                   (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (e.id, e.project_id, e.host, e.method, e.url, e.path,
                 e.classification.value, e.risk.value,
                 self._j(e.signals), e.observed_count,
                 self._j(e.status_codes), self._j(e.response_sizes),
                 str(e.first_seen), str(e.last_seen), self._j(e.request_ids), e.notes)
            )
            await self._conn.commit()
        return e

    async def list_endpoints(self, project_id: str, host: str = None,
                              classification: str = None, min_risk: str = None) -> list[Endpoint]:
        clauses = ["project_id=?"]
        args: list = [project_id]
        if host:
            clauses.append("host=?"); args.append(host)
        if classification:
            clauses.append("classification=?"); args.append(classification)
        q = f"SELECT * FROM endpoints WHERE {' AND '.join(clauses)} ORDER BY risk DESC, observed_count DESC"
        async with self._conn.execute(q, args) as cur:
            rows = await cur.fetchall()
        result = []
        for row in rows:
            d = self._row_to_dict(row)
            d["signals"]       = json.loads(d["signals"])
            d["status_codes"]  = json.loads(d["status_codes"])
            d["response_sizes"]= json.loads(d["response_sizes"])
            d["request_ids"]   = json.loads(d["request_ids"])
            result.append(Endpoint(**d))
        return result

    async def get_endpoint(self, endpoint_id: str) -> Optional[Endpoint]:
        async with self._conn.execute("SELECT * FROM endpoints WHERE id=?", (endpoint_id,)) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        d = self._row_to_dict(row)
        d["signals"]        = json.loads(d["signals"])
        d["status_codes"]   = json.loads(d["status_codes"])
        d["response_sizes"] = json.loads(d["response_sizes"])
        d["request_ids"]    = json.loads(d["request_ids"])
        return Endpoint(**d)

    # ── Findings ──────────────────────────────────────────────────────────────

    async def save_finding(self, f: Finding) -> None:
        await self._conn.execute(
            "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (f.id, f.project_id, f.endpoint_id, f.title, f.description,
             f.status.value, f.risk.value, self._j(f.signals),
             f.confidence, self._j(f.evidence), str(f.created_at))
        )
        await self._conn.commit()

    async def list_findings(self, project_id: str) -> list[Finding]:
        async with self._conn.execute(
            "SELECT * FROM findings WHERE project_id=? ORDER BY created_at DESC",
            (project_id,)
        ) as cur:
            rows = await cur.fetchall()
        result = []
        for row in rows:
            d = self._row_to_dict(row)
            d["signals"]  = json.loads(d["signals"])
            d["evidence"] = json.loads(d["evidence"])
            result.append(Finding(**d))
        return result

