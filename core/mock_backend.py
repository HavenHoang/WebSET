#Delete the file when real integration

def run_scan(url: str):
    # Simulate unreachable website
    if "notexist" in url or "invalid" in url:
        return {"error": "unreachable"}

    return [
        {
            "severity": "High",
            "vulnerability": "Missing Security Header",
            "location": url,
            "description": "X-Frame-Options header is missing"
        },
        {
            "severity": "High",
            "vulnerability": "Insecure Cookie",
            "location": url,
            "description": "Cookie without Secure flag"
        },
        {
            "severity": "Medium",
            "vulnerability": "Server Information Disclosure",
            "location": url,
            "description": "Server version is exposed"
        },
        {
            "severity": "Low",
            "vulnerability": "Missing CSP",
            "location": url,
            "description": "Content-Security-Policy header not set"
        }
    ]
