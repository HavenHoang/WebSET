"""Lightweight tech fingerprints (headers, body, filenames) + version patterns."""
from __future__ import annotations
import re
HEADER_RULES = [
    ("Nginx", "Web Server", "", lambda h: "nginx" in h.get("server", "")),
    ("Apache", "Web Server", "", lambda h: "apache" in h.get("server", "")),
    ("IIS", "Web Server", "", lambda h: "iis" in h.get("server", "")),
    ("PHP", "Language", "", lambda h: "php" in h.get("x-powered-by", "") or "php" in h.get("server", "")),
    ("ASP.NET", "Language", "", lambda h: "asp.net" in h.get("x-powered-by", "")),
    ("Express", "Framework", "", lambda h: "express" in h.get("x-powered-by", "") or "express" in h.get("server", "")),
    ("Node.js", "Runtime", "", lambda h: "express" in h.get("x-powered-by", "") or "nodejs" in h.get("x-powered-by", "")),
    ("Cloudflare", "CDN", "", lambda h: "cloudflare" in h.get("server", "") or "cf-ray" in h),
    ("Fastly", "CDN", "", lambda h: "fastly" in h.get("via", "") or "fastly" in h.get("x-served-by", "") or "x-fastly-request-id" in h),
    ("Akamai", "CDN", "", lambda h: "akamai" in h.get("server", "") or "x-akamai-transformed" in h or "x-akamai-request-id" in h),
    ("Amazon CloudFront", "CDN", "", lambda h: "cloudfront" in h.get("via", "") or "x-amz-cf-id" in h),
    ("Varnish", "CDN", "", lambda h: "x-varnish" in h or "varnish" in h.get("via", "")),
]
BODY_RULES = [
    ("WordPress", "CMS", "", lambda b: "wp-content" in b or "wp-includes" in b),
    ("Drupal", "CMS", "", lambda b: ("drupal" in b and "drupal.org" in b) or "drupal.settings" in b),
    ("React", "Frontend", "", lambda b: "data-reactroot" in b or "__reactcontainer" in b or "react-dom" in b),
    ("Angular", "Frontend", "", lambda b: "ng-version" in b or "<app-root" in b or "ng-app" in b or "angular.min.js" in b),
    ("Vue", "Frontend", "", lambda b: "data-v-app" in b or "vue.runtime" in b or "vue.min.js" in b),
    ("Next.js", "Frontend", "", lambda b: "__next" in b or "__next_data__" in b),
    ("jQuery", "Frontend", "", lambda b: "jquery" in b),
    ("Bootstrap", "Frontend", "", lambda b: "bootstrap." in b),
    ("Django", "Framework", "", lambda b: "csrfmiddlewaretoken" in b),
    ("Spring", "Framework", "", lambda b: "whitelabel error page" in b or "jsessionid=" in b),
    ("Express", "Framework", "", lambda b: "x-powered-by: express" in b or "cannot get /" in b),
    ("Sequelize", "Library", "", lambda b: "sequelize" in b or "sequelizedatabaseerror" in b),
    ("Helmet", "Library", "", lambda b: "content-security-policy" in b and "helmet" in b),
    ("Webpack", "Build", "", lambda b: "webpackjsonp" in b or "__webpack_require__" in b),
    ("Socket.IO", "Library", "", lambda b: "socket.io" in b),
]
FILE_RULES = [
    ("PHP", "Language", "", lambda paths: any(p.endswith(".php") for p in paths)),
    ("WordPress", "CMS", "", lambda paths: any("wp-config.php" in p or "/wp-admin/" in p for p in paths)),
    ("Node.js", "Runtime", "", lambda paths: any(p.endswith("package.json") for p in paths)),
    ("Angular", "Frontend", "", lambda paths: any(p.endswith("angular.json") or "/@angular/" in p for p in paths)),
    ("Docker", "Infrastructure", "", lambda paths: any(p.endswith("dockerfile") or "docker-compose" in p for p in paths)),
    ("Java", "Language", "", lambda paths: any(p.endswith(".java") or p.endswith("pom.xml") for p in paths)),
    ("Python", "Language", "", lambda paths: any(p.endswith("requirements.txt") or p.endswith(".py") for p in paths)),
    ("Laravel", "Framework", "", lambda paths: any(p.endswith("artisan") or p.endswith("composer.json") for p in paths)),
    ("SQLite", "Database", "", lambda paths: any(p.endswith((".sqlite", ".sqlite3", ".db")) for p in paths)),
    ("SQL Database", "Database", "", lambda paths: any(p.endswith(".sql") for p in paths)),
]
VERSION_PATTERNS = {
    "Nginx": re.compile(r"nginx/([\d.]+)", re.I),
    "Apache": re.compile(r"apache/([\d.]+)", re.I),
    "IIS": re.compile(r"iis/([\d.]+)", re.I),
    "PHP": re.compile(r"php/([\d.]+)", re.I),
    "WordPress": re.compile(r"wordpress[\"'\s]*([\d]+(?:\.[\d]+)+)", re.I),
    "jQuery": re.compile(r"jquery[.\-/]([\d]+(?:\.[\d]+)+)", re.I),
    "Bootstrap": re.compile(r"bootstrap[.\-/]([\d]+(?:\.[\d]+)+)", re.I),
    "Angular": re.compile(r'ng-version=["\']([\d.]+)', re.I),
    "Express": re.compile(r"express[/-]?([\d.]+)", re.I),
}

# Generic same-origin probes for surface checks. Not target-specific.
INTERESTING_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/favicon.ico",
    "/.well-known/security.txt",
    "/.env",
    "/.git/HEAD",
    "/.git/config",
    "/package.json",
    "/package-lock.json",
    "/composer.json",
    "/web.config",
    "/crossdomain.xml",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/metrics",
    "/health",
    "/status",
    "/info",
    "/debug",
    "/console",
    "/trace",
    "/actuator",
    "/actuator/health",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/graphql",
    "/ftp/",
    "/ftp",
    "/backup/",
    "/backups/",
    "/uploads/",
    "/files/",
    "/static/",
    "/keys/",
    "/encryptionkeys/",
)

def extract_version(name: str, blob: str) -> str:
    pat = VERSION_PATTERNS.get(name)
    if not pat:
        return ""
    m = pat.search(blob or "")
    return m.group(1).strip(".") if m else ""
def stack_item(name: str, category: str, version: str, description: str) -> dict:
    return {
        "name": name,
        "category": category,
        "version": version or "",
        "description": description,
    }
