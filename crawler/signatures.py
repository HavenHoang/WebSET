"""Lightweight tech fingerprints (headers, body, filenames) + version patterns."""
from __future__ import annotations
import re

HEADER_RULES = [
    ("Nginx",  "Web Server", "", lambda h: "nginx" in h.get("server", "")),
    ("Apache", "Web Server", "", lambda h: "apache" in h.get("server", "")),
    ("IIS",    "Web Server", "", lambda h: "iis" in h.get("server", "")),
    ("PHP",    "Language",   "", lambda h: "php" in h.get("x-powered-by", "") or "php" in h.get("server", "")),
    ("ASP.NET","Language",   "", lambda h: "asp.net" in h.get("x-powered-by", "")),
    ("Express","Framework",  "", lambda h: "express" in h.get("x-powered-by", "")),
    # --- CDN / edge (detected from HTTP headers on a live URL) ---
    ("Cloudflare",        "CDN", "", lambda h: "cloudflare" in h.get("server", "") or "cf-ray" in h),
    ("Fastly",            "CDN", "", lambda h: "fastly" in h.get("via", "") or "fastly" in h.get("x-served-by", "") or "x-fastly-request-id" in h),
    ("Akamai",            "CDN", "", lambda h: "akamai" in h.get("server", "") or "x-akamai-transformed" in h or "x-akamai-request-id" in h),
    ("Amazon CloudFront", "CDN", "", lambda h: "cloudfront" in h.get("via", "") or "x-amz-cf-id" in h),
    ("Varnish",           "CDN", "", lambda h: "x-varnish" in h or "varnish" in h.get("via", "")),
]

BODY_RULES = [
    ("WordPress", "CMS",      "", lambda b: "wp-content" in b or "wordpress" in b),
    ("Drupal",    "CMS",      "", lambda b: "drupal" in b),
    ("React",     "Frontend", "", lambda b: "data-reactroot" in b or "__reactcontainer" in b),
    ("Angular",   "Frontend", "", lambda b: "ng-version" in b),
    ("jQuery",    "Frontend", "", lambda b: "jquery" in b),
    ("Bootstrap", "Frontend", "", lambda b: "bootstrap." in b),
    ("Django",    "Framework", "", lambda b: "csrfmiddlewaretoken" in b),
]

FILE_RULES = [
    ("PHP",         "Language",       "", lambda paths: any(p.endswith(".php") for p in paths)),
    ("WordPress",   "CMS",            "", lambda paths: any("wp-config.php" in p or "/wp-admin/" in p for p in paths)),
    ("Node.js",     "Runtime",        "", lambda paths: any(p.endswith("package.json") for p in paths)),
    ("Docker",      "Infrastructure", "", lambda paths: any(p.endswith("dockerfile") or "docker-compose" in p for p in paths)),
    ("Java",        "Language",       "", lambda paths: any(p.endswith(".java") or p.endswith("pom.xml") for p in paths)),
    ("Python",      "Language",       "", lambda paths: any(p.endswith("requirements.txt") or p.endswith(".py") for p in paths)),
    ("Laravel",     "Framework",      "", lambda paths: any("artisan" in p or "composer.json" in p for p in paths)),
    # --- Databases (detected from project files in a static ZIP) ---
    ("SQLite",       "Database",      "", lambda paths: any(p.endswith((".sqlite", ".sqlite3", ".db")) for p in paths)),
    ("SQL Database", "Database",      "", lambda paths: any(p.endswith(".sql") for p in paths)),
]

VERSION_PATTERNS = {
    "Nginx":     re.compile(r"nginx/([\d.]+)", re.I),
    "Apache":    re.compile(r"apache/([\d.]+)", re.I),
    "IIS":       re.compile(r"iis/([\d.]+)", re.I),
    "PHP":       re.compile(r"php/([\d.]+)", re.I),
    "WordPress": re.compile(r"wordpress[\"'\s]*([\d]+(?:\.[\d]+)+)", re.I),
    "jQuery":    re.compile(r"jquery[.\-/]([\d]+(?:\.[\d]+)+)", re.I),
    "Bootstrap": re.compile(r"bootstrap[.\-/]([\d]+(?:\.[\d]+)+)", re.I),
    "Angular":   re.compile(r'ng-version=["\']([\d.]+)', re.I),
}


def extract_version(name: str, blob: str) -> str:
    pat = VERSION_PATTERNS.get(name)
    if not pat:
        return ""
    m = pat.search(blob or "")
    return m.group(1).strip(".") if m else ""


def stack_item(name: str, category: str, version: str, description: str) -> dict:
    return {"name": name, "category": category,
            "version": version or "", "description": description}
