"""Optional JS render path. Keep headless and short-lived."""
from __future__ import annotations
import time
from crawler.scope import normalise_url


def fetch_with_selenium(url: str, *, timeout: float = 20.0) -> dict:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    url = normalise_url(url)
    opts = Options()
    for a in ("--headless=new", "--disable-gpu", "--no-sandbox",
              "--disable-dev-shm-usage", "--window-size=1280,900"):
        opts.add_argument(a)
    opts.page_load_strategy = "normal"
    driver, t0 = None, time.time()
    try:
        driver = webdriver.Chrome(options=opts)
        driver.set_page_load_timeout(timeout)
        driver.get(url)
        return {"ok": True, "url": driver.current_url or url, "status": 200,
                "redirect_chain": [], "headers": {}, "set_cookie": [], "body": driver.page_source or "",
                "elapsed_ms": int((time.time() - t0) * 1000), "error": None}
    except Exception as exc:
        return {"ok": False, "url": url, "status": 0, "redirect_chain": [], "headers": {}, "set_cookie": [],
                "body": "", "elapsed_ms": int((time.time() - t0) * 1000), "error": str(exc)}
    finally:
        if driver is not None:
            try: driver.quit()
            except Exception: pass
