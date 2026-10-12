from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import os
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = 5000
ROOT = os.path.dirname(os.path.abspath(__file__))

api_key = "n7k2m4p8q1w3"
debug = True
jwt_secret = "n7k2m4p8q1w3"


def build_query(term):
    return "SELECT id FROM notes WHERE title = '" + term + "'"


def run_formula(expr):
    return eval(expr)


def run_host_check(host):
    os.system("ping -c 1 " + host)


def weak_digest(text):
    return hashlib.md5(text.encode("utf-8")).hexdigest()


PAGE = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Lab Target</title>
  <script src="/assets/app.js"></script>
</head>
<body>
  <h1>Lab Target</h1>
  <p>Local fixture for an authorised WebSET scan.</p>
  <p><a href="/search?q=hello">Search</a></p>
  <p><a href="/login">Sign in</a></p>
  <p><a href="/files/">Files</a></p>
  <form method="POST" action="/login">
    <label>Username <input name="username"></label>
    <label>Password <input name="password" type="password"></label>
    <button type="submit">Sign in</button>
  </form>
</body>
</html>
"""

SEARCH_PAGE = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Search</title></head>
<body>
  <h1>Search</h1>
  <form method="GET" action="/search">
    <input name="q" value="{value}">
    <button type="submit">Search</button>
  </form>
  <p>Results for: {value}</p>
  {extra}
  <p><a href="/">Home</a></p>
</body>
</html>
"""

LOGIN_PAGE = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Sign in</title></head>
<body>
  <h1>Sign in</h1>
  <form method="POST" action="/login">
    <label>Username <input name="username"></label>
    <label>Password <input name="password" type="password"></label>
    <button type="submit">Sign in</button>
  </form>
  <p><a href="/">Home</a></p>
</body>
</html>
"""

LISTING_PAGE = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Index of /files/</title></head>
<body>
  <h1>Index of /files/</h1>
  <ul>
    <li><a href="/files/">Parent Directory</a></li>
    <li><a href="/files/notes.bak">notes.bak</a></li>
    <li><a href="/files/dump.sql">dump.sql</a></li>
  </ul>
</body>
</html>
"""

NOTES_BAK = "backup copy of lab notes\ncustomer list\ninternal only\n"
DUMP_SQL = "-- lab dump\nCREATE TABLE notes (id INT, title TEXT);\n"


def _sql_fault(value):
    if "'" not in (value or ""):
        return ""
    return (
        "<pre>sqlite3.OperationalError: unrecognized token: "
        + value
        + "</pre>"
    )


class Handler(BaseHTTPRequestHandler):
    server_version = "LabApp/1.2"
    sys_version = ""

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def _send(self, status, body, content_type="text/html; charset=utf-8", extra=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "LabApp/1.2")
        self.send_header("Set-Cookie", "session=42; Path=/")
        for name, value in extra or []:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path or "/"
        query = parse_qs(parsed.query, keep_blank_values=True)

        if path in ("/", "/index.html"):
            self._send(200, PAGE)
            return
        if path == "/search":
            value = (query.get("q") or [""])[0]
            self._send(200, SEARCH_PAGE.format(value=value, extra=_sql_fault(value)))
            return
        if path == "/login":
            self._send(200, LOGIN_PAGE)
            return
        if path in ("/files", "/files/"):
            self._send(200, LISTING_PAGE)
            return
        if path == "/files/notes.bak":
            self._send(200, NOTES_BAK, "text/plain; charset=utf-8")
            return
        if path == "/files/dump.sql":
            self._send(200, DUMP_SQL, "text/plain; charset=utf-8")
            return
        if path == "/assets/app.js":
            with open(os.path.join(ROOT, "assets", "app.js"), encoding="utf-8") as handle:
                self._send(200, handle.read(), "text/javascript; charset=utf-8")
            return
        if path == "/redirect":
            target = (query.get("url") or query.get("next") or ["/"])[0]
            self._send(302, "", extra=[("Location", target or "/")])
            return
        self._send(404, "<h1>Not found</h1>")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        fields = parse_qs(raw, keep_blank_values=True)
        username = (fields.get("username") or [""])[0]
        if "'" in username:
            self._send(200, LOGIN_PAGE + _sql_fault(username))
            return
        self._send(200, "<h1>Signed in</h1><p><a href=\"/\">Home</a></p>")


def main():
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print("Lab target on http://%s:%s/  (this machine only)" % (HOST, PORT))
    print("Stop with Ctrl+C")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
