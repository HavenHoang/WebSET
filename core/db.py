import sqlite3
import os
import json
import hashlib
from datetime import datetime

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "webset.db",
)
ARCHIVE_USERNAME = "__system_archive__"
PLATFORM_ORIGIN = "Platform"


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _hash_password(password: str) -> str:
    """Simple SHA-256 hash for prototype (not production-grade)."""
    return hashlib.sha256((password or "").encode("utf-8")).hexdigest()


def _migrate_findings_columns(cur):
    """Add remediation / nist / sans if an older DB is missing them."""
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
    if not cur.fetchone():
        return
    cur.execute("PRAGMA table_info(findings)")
    cols = {row[1] for row in cur.fetchall()}
    alters = []
    if "remediation" not in cols:
        alters.append("ALTER TABLE findings ADD COLUMN remediation TEXT")
    if "nist" not in cols:
        alters.append("ALTER TABLE findings ADD COLUMN nist TEXT")
    if "sans" not in cols:
        alters.append("ALTER TABLE findings ADD COLUMN sans TEXT")
    for sql in alters:
        try:
            cur.execute(sql)
        except sqlite3.OperationalError:
            pass


def init_db():
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cases'")
    if cur.fetchone():
        cur.execute("PRAGMA table_info(cases)")
        cols = [row[1] for row in cur.fetchall()]
        if "user_id" not in cols:
            cur.executescript(
                """
                DROP TABLE IF EXISTS findings;
                DROP TABLE IF EXISTS tech_stacks;
                DROP TABLE IF EXISTS scans;
                DROP TABLE IF EXISTS cases;
                """
            )
            conn.commit()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            password_hash TEXT DEFAULT '',
            role TEXT DEFAULT 'analyst',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            name_key TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, name_key),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            scan_type TEXT DEFAULT 'Dynamic',
            status TEXT DEFAULT 'Complete',
            progress INTEGER DEFAULT 100,
            created_at TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            severity TEXT,
            vulnerability TEXT,
            location TEXT,
            description TEXT,
            remediation TEXT,
            confidence TEXT,
            cwe_id TEXT,
            wasc_id TEXT,
            owasp_tags TEXT,
            nist TEXT,
            sans TEXT,
            plugin_id TEXT,
            message_id TEXT,
            scan_origin TEXT DEFAULT 'Dynamic',
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS tech_stacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            name TEXT,
            category TEXT,
            version TEXT,
            description TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
        """
    )
    cur.execute("PRAGMA table_info(users)")
    user_cols = [row[1] for row in cur.fetchall()]
    if "password_hash" not in user_cols:
        try:
            cur.execute(
                "ALTER TABLE users ADD COLUMN password_hash TEXT DEFAULT ''"
            )
        except sqlite3.OperationalError:
            pass
    _migrate_findings_columns(cur)
    conn.commit()
    conn.close()


def _ensure_archive_user(cur) -> int:
    cur.execute(
        "SELECT id FROM users WHERE username = ?",
        (ARCHIVE_USERNAME,),
    )
    row = cur.fetchone()
    if row:
        return int(row["id"])
    cur.execute(
        """
        INSERT INTO users (username, display_name, password_hash, role, created_at)
        VALUES (?, ?, '', 'system', ?)
        """,
        (
            ARCHIVE_USERNAME,
            "Archived history",
            datetime.now().isoformat(timespec="seconds"),
        ),
    )
    return int(cur.lastrowid)


def register_user(username: str, password: str, display_name: str | None = None) -> dict:
    username = (username or "").strip()
    password = password or ""
    if not username:
        raise ValueError("Username is required.")
    if username == ARCHIVE_USERNAME:
        raise ValueError("Reserved username.")
    if len(password) < 4:
        raise ValueError("Password must be at least 4 characters.")
    display = (display_name or "").strip() or username
    init_db()
    conn = _connect()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO users (username, display_name, password_hash, role, created_at)
            VALUES (?, ?, ?, 'analyst', ?)
            """,
            (
                username,
                display,
                _hash_password(password),
                datetime.now().isoformat(timespec="seconds"),
            ),
        )
        conn.commit()
        user_id = int(cur.lastrowid)
    except sqlite3.IntegrityError:
        conn.close()
        raise ValueError("Username already exists.")
    conn.close()
    return {"id": user_id, "username": username, "display_name": display}


def authenticate_user(username: str, password: str) -> dict | None:
    username = (username or "").strip()
    if not username or username == ARCHIVE_USERNAME:
        return None
    init_db()
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, username, display_name, password_hash
        FROM users WHERE username = ?
        """,
        (username,),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    stored = row["password_hash"] or ""
    if not stored:
        return None
    if stored != _hash_password(password):
        return None
    return {
        "id": int(row["id"]),
        "username": row["username"],
        "display_name": row["display_name"],
    }


def list_users() -> list:
    init_db()
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, username, display_name, role, created_at
        FROM users
        WHERE username != ?
        ORDER BY id ASC
        """,
        (ARCHIVE_USERNAME,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_user(user_id: int) -> dict | None:
    init_db()
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, username, display_name, role, created_at
        FROM users WHERE id = ? AND username != ?
        """,
        (user_id, ARCHIVE_USERNAME),
    )
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def delete_user(user_id: int) -> bool:
    init_db()
    conn = _connect()
    cur = conn.cursor()
    uid = int(user_id)
    cur.execute("SELECT id, username FROM users WHERE id = ?", (uid,))
    row = cur.fetchone()
    if not row or row["username"] == ARCHIVE_USERNAME:
        conn.close()
        return False
    archive_id = _ensure_archive_user(cur)
    cur.execute(
        "UPDATE cases SET user_id = ? WHERE user_id = ?",
        (archive_id, uid),
    )
    cur.execute("DELETE FROM users WHERE id = ?", (uid,))
    deleted = cur.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def delete_user_by_username(username: str) -> bool:
    init_db()
    username = (username or "").strip()
    if not username or username == ARCHIVE_USERNAME:
        return False
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return False
    return delete_user(int(row["id"]))


def reset_user_profiles():
    init_db()
    conn = _connect()
    cur = conn.cursor()
    archive_id = _ensure_archive_user(cur)
    cur.execute("UPDATE cases SET user_id = ?", (archive_id,))
    cur.execute("DELETE FROM users WHERE id != ?", (archive_id,))
    try:
        cur.execute("DELETE FROM sqlite_sequence WHERE name = 'users'")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()


def clear_user_history(user_id: int):
    init_db()
    conn = _connect()
    cur = conn.cursor()
    uid = int(user_id)
    archive_id = _ensure_archive_user(cur)
    if uid == archive_id:
        conn.close()
        return
    cur.execute(
        "UPDATE cases SET user_id = ? WHERE user_id = ?",
        (archive_id, uid),
    )
    conn.commit()
    conn.close()


def _name_key(application_name: str) -> str:
    return (application_name or "Sample App").strip().lower()


def get_or_create_case(application_name: str, user_id: int) -> int:
    init_db()
    name = (application_name or "Sample App").strip() or "Sample App"
    key = _name_key(name)
    uid = int(user_id)
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        "SELECT id FROM cases WHERE user_id = ? AND name_key = ?",
        (uid, key),
    )
    row = cur.fetchone()
    if row:
        case_id = row["id"]
    else:
        cur.execute(
            """
            INSERT INTO cases (user_id, name, name_key, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (uid, name, key, datetime.now().isoformat(timespec="seconds")),
        )
        case_id = cur.lastrowid
        conn.commit()
    conn.close()
    return case_id


def create_scan(
    case_id: int,
    url: str,
    scan_type: str = "Dynamic",
    status: str = "Complete",
    progress: int = 100,
) -> int:
    init_db()
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO scans (case_id, url, scan_type, status, progress, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            case_id,
            url or "",
            scan_type or "Dynamic",
            status or "Complete",
            progress,
            datetime.now().isoformat(timespec="seconds"),
        ),
    )
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def _finding_row_to_dict(r) -> dict:
    d = dict(r)
    raw = d.get("owasp_tags")
    tags = []
    if raw:
        try:
            parsed = json.loads(raw)
            tags = parsed if isinstance(parsed, list) else [str(parsed)]
        except Exception:
            tags = [t.strip() for t in str(raw).split(",") if t.strip()]
    d["owasp_tags"] = tags
    d["tags"] = tags
    owasp = None
    for t in tags:
        s = str(t)
        if s.startswith("OWASP-"):
            owasp = s.replace("OWASP-", "")
            break
        if s.startswith("A0") and len(s) <= 4:
            owasp = s
            break
    d["owasp"] = owasp or d.get("owasp")
    d["url"] = d.get("location") or d.get("url") or ""
    d["remediation"] = d.get("remediation") or ""
    d["nist"] = d.get("nist") or ""
    d["sans"] = d.get("sans") or ""
    return d


def save_findings(scan_id: int, findings: list, scan_origin: str = "Dynamic"):
    if not findings:
        return
    # ========== DELETE when Member 1 always returns full CWE/WASC/OWASP/NIST/SANS fields ==========
    try:
        from core.cwe_map import enrich_finding
    except Exception:
        enrich_finding = lambda x: dict(x or {})
    # ========== DELETE end ==========
    # ========== UNCOMMENT when Member 1 always returns full metadata ==========
    # enrich_finding = lambda x: dict(x or {})
    # ========== UNCOMMENT end ==========
    conn = _connect()
    cur = conn.cursor()
    for raw in findings:
        # ========== DELETE when Member 1 always returns full metadata ==========
        f = enrich_finding(raw)
        # ========== DELETE end ==========
        # ========== UNCOMMENT when Member 1 always returns full metadata ==========
        # f = dict(raw or {})
        # ========== UNCOMMENT end ==========
        tags = f.get("tags") or f.get("owasp_tags") or []
        if f.get("owasp") and f"OWASP-{f['owasp']}" not in tags:
            tags = list(tags) + [f"OWASP-{f['owasp']}"]
        if isinstance(tags, list):
            owasp_s = json.dumps(tags)
        else:
            owasp_s = str(tags) if tags else "[]"
        origin = f.get("scan_origin") or scan_origin
        cur.execute(
            """
            INSERT INTO findings (
                scan_id, severity, vulnerability, location, description, remediation,
                confidence, cwe_id, wasc_id, owasp_tags, nist, sans,
                plugin_id, message_id, scan_origin
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                f.get("severity", "Low"),
                f.get("vulnerability", f.get("name", "Finding")),
                f.get("location", f.get("url", "")),
                f.get("description", ""),
                f.get("remediation", ""),
                f.get("confidence", "Medium"),
                str(f.get("cwe_id", f.get("cweId", "") or "")),
                str(f.get("wasc_id", f.get("wascId", "") or "")),
                owasp_s,
                str(f.get("nist", f.get("nist_id", "") or "")),
                str(f.get("sans", f.get("sans_id", "") or "")),
                str(f.get("plugin_id", f.get("pluginId", "") or "")),
                str(f.get("message_id", f.get("messageId", "") or "")),
                origin,
            ),
        )
    conn.commit()
    conn.close()


def save_tech_stacks(scan_id: int, stacks: list):
    if not stacks:
        return
    conn = _connect()
    cur = conn.cursor()
    for s in stacks:
        cur.execute(
            """
            INSERT INTO tech_stacks (scan_id, name, category, version, description)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                s.get("name", ""),
                s.get("category", ""),
                s.get("version", ""),
                s.get("description", ""),
            ),
        )
    conn.commit()
    conn.close()


def save_full_scan(
    application_name: str,
    url: str,
    scan_type: str,
    findings: list,
    tech_stacks=None,
    user_id: int | None = None,
):
    """Start Scan path — stores scan findings only (not platform notes)."""
    if user_id is None:
        raise ValueError("user_id is required. Sign in before saving a scan.")
    # ========== DELETE when Member 1 always returns full CWE/WASC/OWASP/NIST/SANS fields ==========
    try:
        from core.cwe_map import enrich_findings
        findings = enrich_findings(findings or [])
    except Exception:
        findings = findings or []
    # ========== DELETE end ==========
    # ========== UNCOMMENT when Member 1 always returns full metadata ==========
    # findings = findings or []
    # ========== UNCOMMENT end ==========
    case_id = get_or_create_case(application_name, user_id=int(user_id))
    scan_id = create_scan(case_id, url, scan_type=scan_type)
    origin = scan_type if scan_type in ("Dynamic", "Static") else "Dynamic"
    save_findings(scan_id, findings, scan_origin=origin)
    if tech_stacks:
        save_tech_stacks(scan_id, tech_stacks)
    return {
        "case_id": case_id,
        "scan_id": scan_id,
        "user_id": int(user_id),
        "findings": findings,
    }


def update_scan_findings_and_stacks(
    scan_id: int,
    findings: list | None = None,
    tech_stacks: list | None = None,
    stack_findings: list | None = None,
) -> bool:
    """
    Update an existing scan without mixing Start Scan and Get Stack results.

    - findings: if not None → replace non-Platform findings (Start Scan results)
    - stack_findings: if not None → replace Platform-origin findings only
    - tech_stacks: if not None → replace tech stack rows

    Get Stack path should pass stack_findings + tech_stacks (findings=None).
    """
    if scan_id is None:
        return False
    init_db()
    sid = int(scan_id)
    conn = _connect()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT id, scan_type FROM scans WHERE id = ?",
            (sid,),
        )
        row = cur.fetchone()
        if not row:
            conn.close()
            return False
        origin = row["scan_type"] if row["scan_type"] in ("Dynamic", "Static") else "Dynamic"

        if findings is not None:
            # Remove Start Scan findings only — keep Platform rows
            cur.execute(
                """
                DELETE FROM findings
                WHERE scan_id = ?
                  AND IFNULL(scan_origin, '') != ?
                """,
                (sid, PLATFORM_ORIGIN),
            )
        if stack_findings is not None:
            cur.execute(
                """
                DELETE FROM findings
                WHERE scan_id = ?
                  AND scan_origin = ?
                """,
                (sid, PLATFORM_ORIGIN),
            )
        if tech_stacks is not None:
            cur.execute("DELETE FROM tech_stacks WHERE scan_id = ?", (sid,))
        conn.commit()
        conn.close()
    except Exception as e:
        try:
            conn.rollback()
            conn.close()
        except Exception:
            pass
        print("update_scan_findings_and_stacks clear error:", e)
        return False

    if findings is not None:
        save_findings(sid, findings or [], scan_origin=origin)
    if stack_findings is not None and stack_findings:
        # Force Platform origin for Get Stack evaluation notes
        tagged = []
        for f in stack_findings:
            d = dict(f or {})
            d["scan_origin"] = PLATFORM_ORIGIN
            tagged.append(d)
        save_findings(sid, tagged, scan_origin=PLATFORM_ORIGIN)
    if tech_stacks is not None and tech_stacks:
        save_tech_stacks(sid, tech_stacks)
    return True


def list_scans(limit: int = 50, user_id: int | None = None) -> list:
    init_db()
    conn = _connect()
    cur = conn.cursor()
    if user_id is not None:
        cur.execute(
            """
            SELECT
                s.id AS scan_id,
                c.id AS case_id,
                c.name AS case_name,
                c.user_id AS user_id,
                u.display_name AS user_name,
                s.url AS url,
                s.scan_type AS scan_type,
                s.status AS status,
                s.progress AS progress,
                s.created_at AS created_at,
                (SELECT COUNT(*) FROM findings f
                 WHERE f.scan_id = s.id
                   AND IFNULL(f.scan_origin, '') != 'Platform') AS findings_count,
                (SELECT COUNT(*) FROM findings f
                 WHERE f.scan_id = s.id
                   AND f.scan_origin = 'Platform') AS platform_findings_count,
                (SELECT COUNT(*) FROM cases c2
                 WHERE c2.user_id = c.user_id AND c2.id <= c.id) AS user_case_no,
                (SELECT COUNT(*) FROM scans s2
                 JOIN cases c2 ON c2.id = s2.case_id
                 WHERE c2.user_id = c.user_id AND s2.id <= s.id) AS user_scan_no
            FROM scans s
            JOIN cases c ON c.id = s.case_id
            JOIN users u ON u.id = c.user_id
            WHERE c.user_id = ?
            ORDER BY s.id DESC
            LIMIT ?
            """,
            (user_id, limit),
        )
    else:
        cur.execute(
            """
            SELECT
                s.id AS scan_id,
                c.id AS case_id,
                c.name AS case_name,
                c.user_id AS user_id,
                u.display_name AS user_name,
                s.url AS url,
                s.scan_type AS scan_type,
                s.status AS status,
                s.progress AS progress,
                s.created_at AS created_at,
                (SELECT COUNT(*) FROM findings f
                 WHERE f.scan_id = s.id
                   AND IFNULL(f.scan_origin, '') != 'Platform') AS findings_count,
                (SELECT COUNT(*) FROM findings f
                 WHERE f.scan_id = s.id
                   AND f.scan_origin = 'Platform') AS platform_findings_count,
                (SELECT COUNT(*) FROM cases c2
                 WHERE c2.user_id = c.user_id AND c2.id <= c.id) AS user_case_no,
                (SELECT COUNT(*) FROM scans s2
                 JOIN cases c2 ON c2.id = s2.case_id
                 WHERE c2.user_id = c.user_id AND s2.id <= s.id) AS user_scan_no
            FROM scans s
            JOIN cases c ON c.id = s.case_id
            JOIN users u ON u.id = c.user_id
            ORDER BY s.id DESC
            LIMIT ?
            """,
            (limit,),
        )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def list_cases(user_id: int | None = None) -> list:
    init_db()
    conn = _connect()
    cur = conn.cursor()
    if user_id is not None:
        cur.execute(
            """
            SELECT
                c.id AS case_id,
                c.name AS case_name,
                c.user_id AS user_id,
                u.display_name AS user_name,
                c.created_at AS created_at,
                (SELECT COUNT(*) FROM scans s WHERE s.case_id = c.id) AS scan_count,
                (SELECT COUNT(*) FROM cases c2
                 WHERE c2.user_id = c.user_id AND c2.id <= c.id) AS user_case_no
            FROM cases c
            JOIN users u ON u.id = c.user_id
            WHERE c.user_id = ?
            ORDER BY c.id DESC
            """,
            (user_id,),
        )
    else:
        cur.execute(
            """
            SELECT
                c.id AS case_id,
                c.name AS case_name,
                c.user_id AS user_id,
                u.display_name AS user_name,
                c.created_at AS created_at,
                (SELECT COUNT(*) FROM scans s WHERE s.case_id = c.id) AS scan_count,
                (SELECT COUNT(*) FROM cases c2
                 WHERE c2.user_id = c.user_id AND c2.id <= c.id) AS user_case_no
            FROM cases c
            JOIN users u ON u.id = c.user_id
            ORDER BY c.id DESC
            """
        )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def list_scans_for_case(case_id: int) -> list:
    init_db()
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            s.id AS scan_id,
            s.url AS url,
            s.scan_type AS scan_type,
            s.status AS status,
            s.progress AS progress,
            s.created_at AS created_at,
            (SELECT COUNT(*) FROM findings f
             WHERE f.scan_id = s.id
               AND IFNULL(f.scan_origin, '') != 'Platform') AS findings_count,
            (SELECT COUNT(*) FROM findings f
             WHERE f.scan_id = s.id
               AND f.scan_origin = 'Platform') AS platform_findings_count
        FROM scans s
        WHERE s.case_id = ?
        ORDER BY s.id DESC
        """,
        (int(case_id),),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_scan_by_id(scan_id: int) -> dict | None:
    init_db()
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            s.id AS scan_id,
            s.case_id AS case_id,
            s.url AS url,
            s.scan_type AS scan_type,
            s.status AS status,
            s.progress AS progress,
            s.created_at AS created_at,
            c.name AS case_name,
            c.user_id AS user_id
        FROM scans s
        JOIN cases c ON c.id = s.case_id
        WHERE s.id = ?
        """,
        (int(scan_id),),
    )
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def get_findings(scan_id: int) -> list:
    init_db()
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT severity, vulnerability, location, description, remediation,
               confidence, cwe_id, wasc_id, owasp_tags, nist, sans,
               plugin_id, message_id, scan_origin
        FROM findings WHERE scan_id = ?
        ORDER BY
            CASE severity
                WHEN 'High' THEN 1
                WHEN 'Medium' THEN 2
                WHEN 'Low' THEN 3
                ELSE 4
            END,
            id ASC
        """,
        (scan_id,),
    )
    rows = [_finding_row_to_dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def list_findings_for_scan(scan_id: int) -> list:
    """All findings for one scan (scan + platform). Caller may split by scan_origin."""
    rows = get_findings(int(scan_id))
    # ========== DELETE when Member 1 always returns full CWE/WASC/OWASP/NIST/SANS fields ==========
    try:
        from core.cwe_map import enrich_findings
        return enrich_findings(rows)
    except Exception:
        return rows
    # ========== DELETE end ==========
    # ========== UNCOMMENT when Member 1 always returns full metadata ==========
    # return rows
    # ========== UNCOMMENT end ==========


def list_scan_findings_split(scan_id: int) -> dict:
    """
    Returns:
      {
        "findings": [...],          # Start Scan (Dynamic/Static)
        "stack_findings": [...],    # Get Stack Platform notes
      }
    """
    all_rows = list_findings_for_scan(scan_id)
    scan_rows = []
    platform_rows = []
    for f in all_rows:
        origin = str(f.get("scan_origin") or "")
        if origin == PLATFORM_ORIGIN:
            platform_rows.append(f)
        else:
            scan_rows.append(f)
    return {"findings": scan_rows, "stack_findings": platform_rows}


def get_tech_stacks_for_scan(scan_id: int) -> list:
    init_db()
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT name, category, version, description
        FROM tech_stacks WHERE scan_id = ?
        ORDER BY id ASC
        """,
        (int(scan_id),),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def delete_case(case_id: int, user_id: int) -> bool:
    init_db()
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        "SELECT id FROM cases WHERE id = ? AND user_id = ?",
        (int(case_id), int(user_id)),
    )
    if not cur.fetchone():
        conn.close()
        return False
    cur.execute(
        "DELETE FROM cases WHERE id = ? AND user_id = ?",
        (int(case_id), int(user_id)),
    )
    deleted = cur.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def list_findings_by_origin(scan_origin: str | None = None, limit: int = 100) -> list:
    init_db()
    conn = _connect()
    cur = conn.cursor()
    if scan_origin:
        cur.execute(
            """
            SELECT
                f.severity, f.vulnerability, f.location, f.description, f.remediation,
                f.confidence, f.cwe_id, f.wasc_id, f.owasp_tags, f.nist, f.sans,
                f.plugin_id, f.message_id, f.scan_origin,
                s.scan_type, s.url, c.name AS case_name, s.created_at
            FROM findings f
            JOIN scans s ON s.id = f.scan_id
            JOIN cases c ON c.id = s.case_id
            WHERE f.scan_origin = ? OR s.scan_type = ?
            ORDER BY f.id DESC
            LIMIT ?
            """,
            (scan_origin, scan_origin, limit),
        )
    else:
        cur.execute(
            """
            SELECT
                f.severity, f.vulnerability, f.location, f.description, f.remediation,
                f.confidence, f.cwe_id, f.wasc_id, f.owasp_tags, f.nist, f.sans,
                f.plugin_id, f.message_id, f.scan_origin,
                s.scan_type, s.url, c.name AS case_name, s.created_at
            FROM findings f
            JOIN scans s ON s.id = f.scan_id
            JOIN cases c ON c.id = s.case_id
            ORDER BY f.id DESC
            LIMIT ?
            """,
            (limit,),
        )
    rows = []
    for r in cur.fetchall():
        d = _finding_row_to_dict(r)
        if not d.get("scan_origin"):
            d["scan_origin"] = d.get("scan_type") or "Dynamic"
        rows.append(d)
    conn.close()
    return rows


def get_dashboard_stats(user_id: int | None = None) -> dict:
    init_db()
    conn = _connect()
    cur = conn.cursor()
    if user_id is not None:
        cur.execute("SELECT COUNT(*) AS n FROM cases WHERE user_id = ?", (user_id,))
        cases = cur.fetchone()["n"]
        cur.execute(
            """
            SELECT COUNT(*) AS n FROM scans s
            JOIN cases c ON c.id = s.case_id WHERE c.user_id = ?
            """,
            (user_id,),
        )
        scans = cur.fetchone()["n"]
        cur.execute(
            """
            SELECT COUNT(*) AS n FROM findings f
            JOIN scans s ON s.id = f.scan_id
            JOIN cases c ON c.id = s.case_id WHERE c.user_id = ?
            """,
            (user_id,),
        )
        findings = cur.fetchone()["n"]
        cur.execute(
            """
            SELECT COUNT(DISTINCT t.name) AS n FROM tech_stacks t
            JOIN scans s ON s.id = t.scan_id
            JOIN cases c ON c.id = s.case_id WHERE c.user_id = ?
            """,
            (user_id,),
        )
        technologies = cur.fetchone()["n"]
    else:
        cur.execute("SELECT COUNT(*) AS n FROM cases")
        cases = cur.fetchone()["n"]
        cur.execute("SELECT COUNT(*) AS n FROM scans")
        scans = cur.fetchone()["n"]
        cur.execute("SELECT COUNT(*) AS n FROM findings")
        findings = cur.fetchone()["n"]
        cur.execute("SELECT COUNT(DISTINCT name) AS n FROM tech_stacks")
        technologies = cur.fetchone()["n"]

    if user_id is not None:
        cur.execute(
            """
            SELECT f.severity, COUNT(*) AS n FROM findings f
            JOIN scans s ON s.id = f.scan_id
            JOIN cases c ON c.id = s.case_id
            WHERE c.user_id = ?
            GROUP BY f.severity
            """,
            (user_id,),
        )
    else:
        cur.execute("SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity")
    severity = {r["severity"]: r["n"] for r in cur.fetchall()}
    high = int(severity.get("High", 0) or 0)
    medium = int(severity.get("Medium", 0) or 0)
    low = int(severity.get("Low", 0) or 0)

    owasp_counts = {}
    if user_id is not None:
        cur.execute(
            """
            SELECT f.owasp_tags FROM findings f
            JOIN scans s ON s.id = f.scan_id
            JOIN cases c ON c.id = s.case_id
            WHERE c.user_id = ? AND f.owasp_tags IS NOT NULL AND f.owasp_tags != ''
            """,
            (user_id,),
        )
    else:
        cur.execute(
            """
            SELECT owasp_tags FROM findings
            WHERE owasp_tags IS NOT NULL AND owasp_tags != ''
            """
        )
    for r in cur.fetchall():
        raw = r["owasp_tags"]
        try:
            parsed = json.loads(raw)
            tags = parsed if isinstance(parsed, list) else [str(parsed)]
        except Exception:
            tags = [t.strip() for t in str(raw).split(",") if t.strip()]
        for t in tags:
            key = str(t).strip()
            if key.startswith("OWASP-"):
                key = key.replace("OWASP-", "")
            if key.startswith("A0") or key.startswith("OWASP"):
                owasp_counts[key] = owasp_counts.get(key, 0) + 1

    def _count_col(col: str) -> dict:
        out = {}
        if user_id is not None:
            cur.execute(
                f"""
                SELECT f.{col} AS k, COUNT(*) AS n FROM findings f
                JOIN scans s ON s.id = f.scan_id
                JOIN cases c ON c.id = s.case_id
                WHERE c.user_id = ? AND f.{col} IS NOT NULL AND f.{col} != ''
                GROUP BY f.{col}
                """,
                (user_id,),
            )
        else:
            cur.execute(
                f"""
                SELECT {col} AS k, COUNT(*) AS n FROM findings
                WHERE {col} IS NOT NULL AND {col} != ''
                GROUP BY {col}
                """
            )
        for r in cur.fetchall():
            out[str(r["k"])] = int(r["n"])
        return out

    cwe_counts = _count_col("cwe_id")
    nist_counts = _count_col("nist")
    sans_counts = _count_col("sans")

    if user_id is not None:
        cur.execute(
            """
            SELECT t.name AS name, COUNT(*) AS n FROM tech_stacks t
            JOIN scans s ON s.id = t.scan_id
            JOIN cases c ON c.id = s.case_id
            WHERE c.user_id = ? AND t.name IS NOT NULL AND t.name != ''
            GROUP BY t.name ORDER BY n DESC LIMIT 8
            """,
            (user_id,),
        )
    else:
        cur.execute(
            """
            SELECT name, COUNT(*) AS n FROM tech_stacks
            WHERE name IS NOT NULL AND name != ''
            GROUP BY name ORDER BY n DESC LIMIT 8
            """
        )
    top_tech = [{"name": r["name"], "count": r["n"]} for r in cur.fetchall()]

    if user_id is not None:
        cur.execute(
            """
            SELECT f.severity, COUNT(*) AS n FROM findings f
            JOIN scans s ON s.id = f.scan_id
            JOIN cases c ON c.id = s.case_id
            WHERE c.user_id = ? AND (f.scan_origin = 'Static' OR s.scan_type = 'Static')
            GROUP BY f.severity
            """,
            (user_id,),
        )
    else:
        cur.execute(
            """
            SELECT f.severity, COUNT(*) AS n FROM findings f
            JOIN scans s ON s.id = f.scan_id
            WHERE f.scan_origin = 'Static' OR s.scan_type = 'Static'
            GROUP BY f.severity
            """
        )
    static_severity = {r["severity"]: r["n"] for r in cur.fetchall()}

    if user_id is not None:
        cur.execute(
            """
            SELECT f.severity, f.vulnerability, f.location, f.description, f.remediation,
                   f.confidence, f.cwe_id, f.wasc_id, f.owasp_tags, f.nist, f.sans, f.scan_origin
            FROM findings f
            JOIN scans s ON s.id = f.scan_id
            JOIN cases c ON c.id = s.case_id
            WHERE c.user_id = ?
            ORDER BY f.id DESC LIMIT 20
            """,
            (user_id,),
        )
    else:
        cur.execute(
            """
            SELECT severity, vulnerability, location, description, remediation,
                   confidence, cwe_id, wasc_id, owasp_tags, nist, sans, scan_origin
            FROM findings ORDER BY id DESC LIMIT 20
            """
        )
    recent_findings = [_finding_row_to_dict(r) for r in cur.fetchall()]
    conn.close()
    return {
        "cases": cases,
        "scans": scans,
        "findings": findings,
        "technologies": technologies,
        "severity": severity,
        "high": high,
        "medium": medium,
        "low": low,
        "owasp_counts": owasp_counts,
        "cwe_counts": cwe_counts,
        "nist_counts": nist_counts,
        "sans_counts": sans_counts,
        "top_tech_stacks": top_tech,
        "static_severity": static_severity,
        "recent_findings": recent_findings,
    }


def get_findings_per_scan(limit: int = 8) -> list:
    init_db()
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            s.id AS scan_id,
            c.name AS case_name,
            s.created_at AS created_at,
            (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS total,
            (SELECT COUNT(*) FROM findings f
             WHERE f.scan_id = s.id AND f.severity = 'High') AS high_count
        FROM scans s
        JOIN cases c ON c.id = s.case_id
        ORDER BY s.id ASC
        LIMIT ?
        """,
        (limit,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def clear_all_data():
    init_db()
    conn = _connect()
    cur = conn.cursor()
    cur.executescript(
        """
        DELETE FROM findings;
        DELETE FROM tech_stacks;
        DELETE FROM scans;
        DELETE FROM cases;
        """
    )
    try:
        cur.execute(
            "DELETE FROM sqlite_sequence WHERE name IN "
            "('cases', 'scans', 'findings', 'tech_stacks')"
        )
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()
