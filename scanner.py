# scanner.py
import socket
import ssl
import datetime
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]

def normalize_url(url: str) -> str:
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url  # prefer https by default
    return url

def check_http_status(url: str) -> dict:
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        return {"ok": True, "status_code": resp.status_code, "headers": resp.headers, "text": resp.text}
    except requests.exceptions.SSLError:
        return {"ok": False, "error": "SSL Error (invalid/expired certificate or handshake failed)"}
    except requests.exceptions.RequestException as e:
        return {"ok": False, "error": str(e)}

def check_security_headers(headers: dict) -> dict:
    missing = []
    present = []
    for h in SECURITY_HEADERS:
        if h in headers:
            present.append(h)
        else:
            missing.append(h)
    return {"missing": missing, "present": present}

def check_ssl_expiry(hostname: str, port: int = 443) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {"ok": False, "error": "No certificate retrieved"}
                not_after = cert.get("notAfter")
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.datetime.utcnow()).days
                return {"ok": True, "expiry": expiry.isoformat(), "days_left": days_left}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def detect_mixed_content(url: str, html_text: str) -> dict:
    parsed = urlparse(url)
    secure = parsed.scheme == "https"
    mixed_items = []
    if not secure:
        return {"secure_scheme": False, "mixed": mixed_items}
    soup = BeautifulSoup(html_text, "html.parser")
    tags = soup.find_all(src=True) + soup.find_all(href=True)
    for t in tags:
        for attr in ("src", "href"):
            if t.has_attr(attr):
                val = t[attr]
                if val.startswith("http://"):
                    mixed_items.append(val)
    return {"secure_scheme": True, "mixed": mixed_items}

def server_info(headers: dict) -> dict:
    srv = headers.get("Server", "Unknown")
    return {"server": srv}

def risk_score_findings(status_check: dict, headers_result: dict, ssl_info: dict, mixed_info: dict) -> dict:
    score = 100
    issues = []

    # Status
    if not status_check.get("ok"):
        score -= 40
        issues.append(f"Request failed: {status_check.get('error')}")
    else:
        code = status_check.get("status_code", 0)
        if code >= 400:
            score -= 20
            issues.append(f"HTTP status {code}")

    # SSL
    if not ssl_info.get("ok"):
        score -= 25
        issues.append(f"SSL problem: {ssl_info.get('error')}")
    else:
        days = ssl_info.get("days_left", 0)
        if days < 0:
            score -= 50
            issues.append("SSL certificate expired")
        elif days < 30:
            score -= 10
            issues.append(f"SSL expiring soon ({days} days left)")

    # Security headers
    missing = headers_result.get("missing", [])
    if missing:
        penalty = min(25, 5 * len(missing))
        score -= penalty
        issues.append(f"Missing headers: {', '.join(missing)}")

    # Mixed content
    mixed = mixed_info.get("mixed", [])
    if mixed:
        score -= 20
        issues.append(f"Mixed content detected ({len(mixed)} items)")

    if score < 0:
        score = 0
    severity = "Low"
    if score < 40:
        severity = "High"
    elif score < 70:
        severity = "Medium"

    return {"score": score, "severity": severity, "issues": issues}

def run_basic_scan(url: str) -> dict:
    url = normalize_url(url)
    parsed = urlparse(url)
    hostname = parsed.hostname
    status = check_http_status(url)
    headers = status.get("headers", {}) if status.get("ok") else {}
    headers_result = check_security_headers(headers)
    ssl_info = check_ssl_expiry(hostname) if hostname else {"ok": False, "error": "No hostname"}
    mixed_info = detect_mixed_content(url, status.get("text", "")) if status.get("ok") else {"secure_scheme": False, "mixed": []}
    server = server_info(headers)
    risk = risk_score_findings(status, headers_result, ssl_info, mixed_info)

    return {
        "url": url,
        "status": status,
        "headers_result": headers_result,
        "ssl_info": ssl_info,
        "mixed_info": mixed_info,
        "server": server,
        "risk": risk
    }
