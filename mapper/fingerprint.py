"""
Tech fingerprinter — HTTP headers, body pattern matching (Wappalyzer-style), TLS cert info.
"""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Wappalyzer-style pattern library ────────────────────────────────────────
# Format: { "Technology": { "header"/"body"/"url": ["pattern", ...] } }

PATTERNS: dict[str, dict[str, list[str]]] = {
    # Servers
    "Apache":         {"header": [r"Apache(?:/[\d.]+)?"]},
    "Nginx":          {"header": [r"nginx(?:/[\d.]+)?"]},
    "IIS":            {"header": [r"Microsoft-IIS(?:/[\d.]+)?"]},
    "Cloudflare":     {"header": [r"cloudflare"], "body": [r"__cf_bm|cf-ray"]},
    "LiteSpeed":      {"header": [r"LiteSpeed"]},
    "Caddy":          {"header": [r"Caddy"]},
    "Gunicorn":       {"header": [r"gunicorn"]},
    "Tomcat":         {"header": [r"Apache-Coyote|Tomcat"]},

    # Languages / runtimes
    "PHP":            {"header": [r"X-Powered-By: PHP"], "body": [r"\.php\""]},
    "ASP.NET":        {"header": [r"X-Powered-By: ASP\.NET|X-AspNet-Version"]},
    "Node.js":        {"header": [r"X-Powered-By: Express"]},
    "Ruby on Rails":  {"header": [r"X-Runtime"], "body": [r"data-turbo|rails"]},
    "Django":         {"body": [r"csrfmiddlewaretoken"]},
    "Laravel":        {"body": [r"laravel_session|XSRF-TOKEN"]},

    # CDNs
    "Fastly":         {"header": [r"Fastly-"]},
    "Akamai":         {"header": [r"AkamaiGHost|X-Akamai"]},
    "AWS CloudFront": {"header": [r"CloudFront|x-amz-cf"]},
    "Varnish":        {"header": [r"X-Varnish|Via:.*varnish"]},
    "Sucuri":         {"header": [r"X-Sucuri"]},

    # CMS
    "WordPress":      {"body": [r"/wp-content/|/wp-includes/|wp-json"]},
    "Drupal":         {"body": [r"Drupal|/sites/default/files/"]},
    "Joomla":         {"body": [r"/components/com_|Joomla!"]},
    "Shopify":        {"body": [r"cdn\.shopify\.com|myshopify\.com"]},
    "Squarespace":    {"body": [r"squarespace\.com|static\.squarespace"]},
    "Wix":            {"body": [r"wix\.com|wixstatic\.com"]},
    "Ghost":          {"body": [r"content=\"Ghost"]},
    "Webflow":        {"body": [r"webflow\.com"]},

    # Frameworks / JS
    "React":          {"body": [r"__REACT_APP|react\.development\.js|react\.production\.min\.js|data-reactroot"]},
    "Vue.js":         {"body": [r"vue\.min\.js|vue\.js|__vue__"]},
    "Angular":        {"body": [r"ng-version|angular\.min\.js|angular/core"]},
    "Next.js":        {"body": [r"__NEXT_DATA__|/_next/static"]},
    "Nuxt.js":        {"body": [r"__nuxt|/_nuxt/"]},
    "jQuery":         {"body": [r"jquery(?:\.min)?\.js|jquery/\d"]},
    "Bootstrap":      {"body": [r"bootstrap(?:\.min)?\.css|bootstrap(?:\.min)?\.js"]},

    # Security / Auth
    "reCAPTCHA":      {"body": [r"recaptcha\.net|google\.com/recaptcha"]},
    "Cloudflare Turnstile": {"body": [r"challenges\.cloudflare\.com"]},
    "Stripe":         {"body": [r"js\.stripe\.com"]},

    # Analytics
    "Google Analytics": {"body": [r"google-analytics\.com/analytics\.js|gtag\("]},
    "Hotjar":         {"body": [r"hotjar\.com"]},
    "Mixpanel":       {"body": [r"mixpanel\.com"]},

    # Infra
    "Kubernetes":     {"header": [r"x-k8s|kubernetes"]},
    "Heroku":         {"header": [r"X-Heroku|herokussl"]},
    "Vercel":         {"header": [r"x-vercel-id|x-vercel"]},
    "Netlify":        {"header": [r"X-NF-Request-ID"]},
}


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class TLSInfo:
    issuer: str
    subject: str
    not_before: str
    not_after: str
    days_remaining: int
    san: list[str] = field(default_factory=list)
    expired: bool = False
    error: Optional[str] = None


@dataclass
class FingerprintResult:
    host: str
    url: str
    status_code: Optional[int] = None
    server: str = ""
    powered_by: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    tls: Optional[TLSInfo] = None
    error: Optional[str] = None
    redirects_to: str = ""


# ── TLS ──────────────────────────────────────────────────────────────────────

def _get_tls_info(host: str, port: int = 443, timeout: int = 5) -> TLSInfo:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we want info even on self-signed
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except Exception as exc:
        return TLSInfo("", "", "", "", 0, error=str(exc))

    def _dn(dn_tuple) -> str:
        return ", ".join(f"{k}={v}" for rdn in dn_tuple for k, v in rdn)

    issuer = _dn(cert.get("issuer", []))
    subject = _dn(cert.get("subject", []))
    not_before = cert.get("notBefore", "")
    not_after = cert.get("notAfter", "")

    san: list[str] = []
    for kind, value in cert.get("subjectAltName", []):
        if kind == "DNS":
            san.append(value)

    days_remaining = 0
    expired = False
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            delta = expiry - now
            days_remaining = delta.days
            expired = delta.days < 0
        except Exception:
            pass

    return TLSInfo(
        issuer=issuer,
        subject=subject,
        not_before=not_before,
        not_after=not_after,
        days_remaining=days_remaining,
        san=san,
        expired=expired,
    )


# ── Pattern matching ──────────────────────────────────────────────────────────

def _match_patterns(headers: dict[str, str], body: str) -> list[str]:
    """Return list of detected technology names."""
    headers_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
    found: list[str] = []

    for tech, checks in PATTERNS.items():
        matched = False
        for pattern in checks.get("header", []):
            if re.search(pattern, headers_str, re.IGNORECASE):
                matched = True
                break
        if not matched:
            for pattern in checks.get("body", []):
                if re.search(pattern, body, re.IGNORECASE):
                    matched = True
                    break
        if matched:
            found.append(tech)

    return found


# ── Public API ────────────────────────────────────────────────────────────────

REQUEST_TIMEOUT = 8
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; AttackSurfaceMapper/1.0)"
})


def fingerprint_host(host: str, use_tls: bool = True, timeout: int = REQUEST_TIMEOUT) -> FingerprintResult:
    """
    Fetch HTTP(S) response for host, extract headers, detect technologies, grab TLS info.
    Tries HTTPS first, falls back to HTTP.
    """
    result = FingerprintResult(host=host, url="")

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            resp = SESSION.get(url, timeout=timeout, verify=False, allow_redirects=True)
            result.url = resp.url
            result.status_code = resp.status_code
            result.headers = dict(resp.headers)
            result.server = resp.headers.get("Server", "")
            result.powered_by = resp.headers.get("X-Powered-By", "")

            if resp.url != url:
                result.redirects_to = resp.url

            body = resp.text[:200_000]  # cap at 200 KB for pattern matching
            result.technologies = _match_patterns(dict(resp.headers), body)

            if use_tls and scheme == "https":
                result.tls = _get_tls_info(host, port=443, timeout=timeout)

            return result

        except (requests.exceptions.SSLError,
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout):
            continue  # try next scheme
        except Exception as exc:
            result.error = str(exc)
            return result

    result.error = "Could not connect over HTTP or HTTPS"
    return result
