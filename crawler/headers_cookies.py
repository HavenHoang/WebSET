from __future__ import annotations


def headers_to_dict(raw_headers) -> dict:
    if raw_headers is None:
        return {}
    # Any mapping (dict, CaseInsensitiveDict, email.message) exposes .items()
    if hasattr(raw_headers, "items"):
        try:
            return {str(k): str(v) for k, v in raw_headers.items()}
        except Exception:
            pass
    out = {}
    try:
        for k, v in raw_headers:           # list of pairs
            out[str(k)] = str(v)
    except Exception:
        pass
    return out


def set_cookie_list(raw_headers) -> list:
    if raw_headers is None:
        return []
    items = []
    if hasattr(raw_headers, "get_all"):
        items = raw_headers.get_all("Set-Cookie") or []
    elif hasattr(raw_headers, "getlist"):
        items = raw_headers.getlist("Set-Cookie") or []
    else:
        try:
            v = raw_headers.get("Set-Cookie")
            if v:
                items = [v]
        except Exception:
            items = []
    return [str(x) for x in items if x]
