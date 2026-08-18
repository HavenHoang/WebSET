"""ZIP helpers for static Get Stack / optional Start Scan support."""
from __future__ import annotations
import os
import zipfile

ANALYSABLE_EXT = {
    ".php", ".py", ".js", ".ts", ".java", ".go", ".rb", ".cs",
    ".html", ".htm", ".xml", ".json", ".yml", ".yaml", ".env",
    ".ini", ".cfg", ".conf", ".txt", ".md",
}


def _safe(name: str) -> bool:
    return not (name.startswith("/") or ".." in name.replace("\\", "/").split("/"))


def list_zip_paths(zip_path: str, limit: int = 5000) -> list:
    path = zip_path or ""
    if os.path.isdir(path):
        out = []
        for root, _dirs, files in os.walk(path):
            for f in files:
                out.append(os.path.join(root, f))
                if len(out) >= limit:
                    return out
        return out
    if not path or not os.path.isfile(path):
        return []
    try:
        with zipfile.ZipFile(path, "r") as zf:
            return [n for n in zf.namelist() if not n.endswith("/") and _safe(n)][:limit]
    except zipfile.BadZipFile:
        return []


def open_project_zip(zip_path: str) -> dict:
    path = zip_path or ""
    if not path or not os.path.isfile(path) or not zipfile.is_zipfile(path):
        return {"ok": False, "error": "invalid_zip", "paths": [], "sample_texts": {}}
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = [n for n in zf.namelist() if not n.endswith("/") and _safe(n)]
            if not names:
                return {"ok": False, "error": "empty_zip", "paths": [], "sample_texts": {}}
            analysable = [n for n in names
                          if os.path.splitext(n)[1].lower() in ANALYSABLE_EXT]
            if not analysable:
                return {"ok": False, "error": "no_analyzable_files",
                        "paths": names, "sample_texts": {}}
            samples = {}
            for n in analysable[:20]:
                try:
                    samples[n] = zf.read(n).decode("utf-8", "replace")[:4000]
                except Exception:
                    continue
            return {"ok": True, "error": None, "paths": names, "sample_texts": samples}
    except zipfile.BadZipFile:
        return {"ok": False, "error": "invalid_zip", "paths": [], "sample_texts": {}}
