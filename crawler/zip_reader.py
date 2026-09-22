"""ZIP helpers for static Get Stack / optional Start Scan support."""
from __future__ import annotations

import os
import zipfile

ANALYSABLE_EXT = {
    ".php", ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs",
    ".java", ".go", ".rb", ".cs",
    ".html", ".htm", ".xml", ".json", ".yml", ".yaml", ".env",
    ".ini", ".cfg", ".conf", ".txt",
    ".jsp", ".jspx", ".aspx", ".asp", ".erb", ".vue", ".inc",
    ".properties", ".plist",
}

SKIP_DIR_PARTS = (
    "/node_modules/",
    "/.git/",
    "/dist/",
    "/build/",
    "/coverage/",
    "/.angular/",
    "/vendor/",
    "/__pycache__/",
    "/frontend/dist/",
    "/.next/",
    "/bower_components/",
)

PRIORITY_EXT = (
    ".env", ".php", ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs",
    ".java", ".jsp", ".aspx", ".yml", ".yaml", ".json", ".html",
    ".vue", ".erb", ".inc",
)

INTERESTING_NAME = (
    "route", "server", "app", "auth", "login", "user", "admin",
    "insecurity", "config", "controller", "api", "search", "upload",
    "query", "sql", "exec", "cmd", "redirect", "proxy", "fetch",
    "include", "cookie", "session", "jwt", "crypto", "cors", "csrf",
    "xml", "deserialize", "pickle", "file", "download", "webhook",
)


def _safe(name: str) -> bool:
    return not (name.startswith("/") or ".." in name.replace("\\", "/").split("/"))


def _norm(name: str) -> str:
    return "/" + name.replace("\\", "/").lower()


def _skip_path(name: str) -> bool:
    low = _norm(name)
    if any(part in low for part in SKIP_DIR_PARTS):
        return True
    base = os.path.basename(low)
    if base.endswith((".min.js", ".map", ".d.ts")):
        return True
    if base in {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "readme.md", "changelog.md"}:
        return True
    return False


def _priority(name: str) -> tuple:
    low = _norm(name)
    ext = os.path.splitext(low)[1]
    try:
        ext_rank = PRIORITY_EXT.index(ext)
    except ValueError:
        ext_rank = 50
    interesting = 0 if any(token in low for token in INTERESTING_NAME) else 1
    source_hint = 0 if any(
        p in low for p in (
            "/server/", "/src/", "/lib/", "/routes/", "/app/",
            "/frontend/src/", "/controllers/", "/models/", "/api/",
        )
    ) else 1
    return (interesting, ext_rank, source_hint, low)


def list_zip_paths(zip_path: str, limit: int = 8000) -> list:
    path = zip_path or ""
    if os.path.isdir(path):
        out = []
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "dist", "build"}]
            for f in files:
                out.append(os.path.join(root, f))
                if len(out) >= limit:
                    return out
        return out
    if not path or not os.path.isfile(path):
        return []
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = [n for n in zf.namelist() if not n.endswith("/") and _safe(n)]
            return names[:limit]
    except zipfile.BadZipFile:
        return []


def open_project_zip(zip_path: str, sample_limit: int = 250, sample_chars: int = 40000) -> dict:
    path = zip_path or ""
    if not path or not os.path.isfile(path) or not zipfile.is_zipfile(path):
        return {"ok": False, "error": "invalid_zip", "paths": [], "sample_texts": {}}
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = [n for n in zf.namelist() if not n.endswith("/") and _safe(n)]
            if not names:
                return {"ok": False, "error": "empty_zip", "paths": [], "sample_texts": {}}
            analysable = [
                n for n in names
                if os.path.splitext(n)[1].lower() in ANALYSABLE_EXT and not _skip_path(n)
            ]
            if not analysable:
                return {
                    "ok": False,
                    "error": "no_analyzable_files",
                    "paths": names,
                    "sample_texts": {},
                }
            chosen = sorted(analysable, key=_priority)[:sample_limit]
            samples = {}
            for n in chosen:
                try:
                    samples[n] = zf.read(n).decode("utf-8", "replace")[:sample_chars]
                except Exception:
                    continue
            return {"ok": True, "error": None, "paths": names, "sample_texts": samples}
    except zipfile.BadZipFile:
        return {"ok": False, "error": "invalid_zip", "paths": [], "sample_texts": {}}
