"""
Form & parameter extraction (Start Scan URL).

Produces the request-target shape Member 1 uses to know where inputs live:
    {
      "url": "https://host/login",
      "method": "POST",
      "parameters": [
        {"name": "username", "type": "text",     "location": "body"},
        {"name": "password", "type": "password", "location": "body"},
        {"name": "csrf_token", "type": "hidden", "location": "body"}
      ],
      "technologies": ["PHP", "Apache"]
    }

Uses the standard-library HTML parser (no extra dependency). Member 2 only
extracts inputs -- it does NOT submit forms or send payloads (that is Member 3).
"""
from __future__ import annotations
from html.parser import HTMLParser
from urllib.parse import urljoin
from crawler.tech_detect import detect_tech_names


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"action": a.get("action", ""),
                         "method": (a.get("method") or "GET").upper(),
                         "fields": []}
        elif tag in ("input", "select", "textarea") and self._cur is not None:
            name = a.get("name")
            if not name:
                return
            if tag == "input":
                ftype = a.get("type", "text") or "text"
            else:
                ftype = tag                       # "select" / "textarea"
            self._cur["fields"].append({"name": name, "type": ftype})

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None

    def close(self):
        super().close()
        if self._cur is not None:                 # tolerate an unclosed <form>
            self.forms.append(self._cur)
            self._cur = None


def extract_forms(page: dict, base_url: str | None = None) -> list:
    """Return one request-target dict per <form> found in the page body."""
    body = page.get("body") or ""
    page_url = base_url or page.get("url") or ""
    if not body:
        return []

    parser = _FormParser()
    try:
        parser.feed(body)
        parser.close()
    except Exception:
        pass

    techs = detect_tech_names(page)
    targets = []
    for form in parser.forms:
        method = form["method"] if form["method"] in ("GET", "POST") else "GET"
        location = "body" if method == "POST" else "query"
        action = urljoin(page_url, form["action"]) if form["action"] else page_url
        params = [{"name": f["name"], "type": f["type"], "location": location}
                  for f in form["fields"]]
        targets.append({"url": action, "method": method,
                        "parameters": params, "technologies": techs})
    return targets
