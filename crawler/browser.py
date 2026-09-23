"""Optional JS render path. Keep headless and short-lived."""
from __future__ import annotations
import time
from urllib.parse import urljoin, urlparse
from crawler.scope import normalise_url
_COMMON_LOGINS = (
    ("admin", "password"),
    ("admin", "admin"),
    ("bee", "bug"),
)
def _origin(url: str) -> str:
    raw = normalise_url(url) if url else ""
    p = urlparse(raw if "://" in raw else "http://" + raw)
    if not p.netloc:
        return ""
    scheme = p.scheme or "http"
    return f"{scheme}://{p.netloc}"
def _cookie_record(cookie: dict) -> dict:
    name = str(cookie.get("name") or "")
    value = str(cookie.get("value") or "")
    domain = str(cookie.get("domain") or "")
    path = str(cookie.get("path") or "/")
    return {
        "name": name,
        "value": value,
        "domain": domain,
        "path": path,
        "secure": bool(cookie.get("secure")),
        "httpOnly": bool(cookie.get("httpOnly") or cookie.get("http_only")),
        "raw": f"{name}={value}",
    }
def _apply_cookies(driver, url: str, cookies: list | None) -> None:
    """
    Selenium can only add cookies for the current origin.
    Open the origin first, then attach caller-supplied cookies.
    """
    if not cookies:
        return
    origin = _origin(url)
    if not origin:
        return
    try:
        current = driver.current_url or ""
        if _origin(current) != origin:
            driver.get(origin)
            time.sleep(0.2)
    except Exception:
        return
    for item in cookies:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        value = str(item.get("value") or "")
        if not name:
            raw = str(item.get("raw") or "")
            if "=" in raw:
                name, value = raw.split("=", 1)
            else:
                continue
        payload = {
            "name": name,
            "value": value,
            "path": str(item.get("path") or "/"),
        }
        domain = str(item.get("domain") or "").strip()
        if domain:
            payload["domain"] = domain
        try:
            driver.add_cookie(payload)
        except Exception:
            try:
                payload.pop("domain", None)
                driver.add_cookie(payload)
            except Exception:
                continue
def _logged_in(html: str) -> bool:
    low = (html or "").lower()
    return "logout" in low or "log out" in low
def _dom_hrefs(driver) -> list[str]:
    """href + location.hash from the rendered page (SPA routes included)."""
    try:
        raw = driver.execute_script(
            """
            const out = [];
            document.querySelectorAll('[href]').forEach(el => {
              const v = el.getAttribute('href');
              if (v) out.push(v);
            });
            if (location.hash) out.push(location.hash);
            return out;
            """
        ) or []
    except Exception:
        raw = []
    seen = set()
    out = []
    for item in raw:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out
def _hrefs_into_body(body: str, hrefs: list[str]) -> str:
    if not hrefs:
        return body or ""
    lines = ["<!-- crawl-links"]
    for href in hrefs[:80]:
        safe = str(href).replace('"', "")
        lines.append(f'<a href="{safe}"></a>')
    lines.append("-->")
    return (body or "") + "\n" + "\n".join(lines)
def _try_default_login(driver) -> None:
    html = ""
    try:
        html = driver.page_source or ""
    except Exception:
        html = ""
    if _logged_in(html):
        return
    low = html.lower()
    if "password" not in low or "<form" not in low:
        return
    from selenium.webdriver.common.by import By
    user_names = ("username", "user", "email", "login")
    pass_names = ("password", "pass", "pwd")
    submit_names = ("Login", "login", "submit")
    user_el = pass_el = None
    for name in user_names:
        try:
            user_el = driver.find_element(By.NAME, name)
            break
        except Exception:
            continue
    for name in pass_names:
        try:
            pass_el = driver.find_element(By.NAME, name)
            break
        except Exception:
            continue
    if user_el is None or pass_el is None:
        return
    for user, password in _COMMON_LOGINS:
        try:
            user_el.clear()
            user_el.send_keys(user)
            pass_el.clear()
            pass_el.send_keys(password)
            clicked = False
            for name in submit_names:
                try:
                    driver.find_element(By.NAME, name).click()
                    clicked = True
                    break
                except Exception:
                    continue
            if not clicked:
                try:
                    pass_el.submit()
                except Exception:
                    continue
            time.sleep(0.6)
            html = driver.page_source or ""
            if _logged_in(html):
                try:
                    driver.add_cookie({"name": "security", "value": "low", "path": "/"})
                except Exception:
                    pass
                origin = _origin(driver.current_url or "")
                if origin:
                    try:
                        driver.get(urljoin(origin + "/", "index.php"))
                        time.sleep(0.3)
                    except Exception:
                        pass
                return
            try:
                user_el = driver.find_element(By.NAME, user_el.get_attribute("name") or "username")
                pass_el = driver.find_element(By.NAME, pass_el.get_attribute("name") or "password")
            except Exception:
                return
        except Exception:
            return
def fetch_with_selenium(
    url: str,
    *,
    timeout: float = 12.0,
    cookies: list | None = None,
    wait_text: str | None = None,
    skip_login: bool = False,
) -> dict:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.support.ui import WebDriverWait
    raw_url = url
    url = normalise_url(url)
    try:
        frag = urlparse(str(raw_url) if "://" in str(raw_url) else "http://" + str(raw_url)).fragment
    except Exception:
        frag = ""
    if frag:
        url = url + "#" + frag
    opts = Options()
    for a in (
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--window-size=1280,900",
        "--disable-background-networking",
        "--disable-extensions",
        "--blink-settings=imagesEnabled=false",
        "--disable-notifications",
    ):
        opts.add_argument(a)
    # eager = DOM ready, do not wait for every third-party script (ads, trackers)
    opts.page_load_strategy = "eager"
    driver = None
    t0 = time.time()
    try:
        driver = webdriver.Chrome(options=opts)
        driver.set_page_load_timeout(timeout)
        driver.set_script_timeout(min(timeout, 8.0))
        _apply_cookies(driver, url, cookies)
        driver.get(url)
        if frag and wait_text:
            try:
                driver.execute_script("window.location.hash = arguments[0];", frag)
            except Exception:
                pass
        deadline = time.time() + max(1.0, float(timeout))
        try:
            WebDriverWait(driver, min(float(timeout), 6)).until(
                lambda d: d.execute_script("return document.readyState")
                in ("interactive", "complete")
            )
        except Exception:
            pass
        if wait_text:
            needle = str(wait_text).lower()
            inner = ""
            while time.time() < deadline:
                try:
                    inner = driver.execute_script(
                        "return document.documentElement ? document.documentElement.outerHTML : '';"
                    ) or ""
                except Exception:
                    inner = ""
                if needle and needle in inner.lower():
                    break
                time.sleep(0.4)
        else:
            time.sleep(0.25)
        if not skip_login:
            _try_default_login(driver)
        if not wait_text:
            try:
                inner = driver.execute_script(
                    "return document.documentElement ? document.documentElement.outerHTML : '';"
                ) or ""
            except Exception:
                inner = ""
        if wait_text:
            body = inner or ""
        else:
            body = inner or (driver.page_source or "")
            hrefs = _dom_hrefs(driver)
            body = _hrefs_into_body(body, hrefs)
        final_url = driver.current_url or url
        collected = []
        try:
            for cookie in driver.get_cookies() or []:
                collected.append(_cookie_record(cookie))
        except Exception:
            collected = []
        return {
            "ok": True,
            "url": final_url,
            "status": 200,
            "redirect_chain": [],
            "headers": {},
            "set_cookie": collected,
            "cookies": collected,
            "body": body,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "error": None,
        }
    except Exception as exc:
        return {
            "ok": False,
            "url": url,
            "status": 0,
            "redirect_chain": [],
            "headers": {},
            "set_cookie": [],
            "cookies": [],
            "body": "",
            "elapsed_ms": int((time.time() - t0) * 1000),
            "error": str(exc),
        }
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass
