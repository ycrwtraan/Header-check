#!/usr/bin/env python3
"""header_check.py - HTTP security header and cookie checker.

Reads one or more URLs, fetches them, and reports missing or weak
security headers and insecure cookie flags. Output is JSON or Markdown.
Can fail a CI job when findings reach a chosen severity.

Only run this against systems you are authorized to test.
Findings are heuristics: validate them manually before reporting.
"""
import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request

SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3}
HSTS_MIN_AGE = 15552000  # 180 days


def fetch(url, timeout, verify_tls):
    """GET the URL (following redirects). Return (final_url, status, headers)."""
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "header-check/1.0"})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
    except urllib.error.HTTPError as err:  # 4xx/5xx still carry useful headers
        resp = err
    with resp:
        return resp.geturl(), resp.getcode(), resp.headers


def finding(severity, title, detail):
    return {"severity": severity, "title": title, "detail": detail}


def check_headers(final_url, headers):
    results = []
    is_https = final_url.lower().startswith("https://")

    # HSTS (only meaningful over HTTPS)
    hsts = headers.get("Strict-Transport-Security")
    if is_https:
        if not hsts:
            results.append(finding("medium", "Missing HSTS",
                                   "Strict-Transport-Security header not set."))
        else:
            m = re.search(r"max-age=(\d+)", hsts, re.I)
            if not m or int(m.group(1)) < HSTS_MIN_AGE:
                results.append(finding("low", "Weak HSTS max-age",
                                       f"Value: {hsts} (recommended >= {HSTS_MIN_AGE})."))

    # CSP
    csp = headers.get("Content-Security-Policy")
    if not csp:
        results.append(finding("medium", "Missing CSP",
                               "Content-Security-Policy header not set."))
    elif re.search(r"unsafe-inline|unsafe-eval", csp, re.I):
        results.append(finding("low", "Weak CSP",
                               "CSP allows 'unsafe-inline' or 'unsafe-eval'."))

    # MIME sniffing
    xcto = headers.get("X-Content-Type-Options", "")
    if xcto.strip().lower() != "nosniff":
        results.append(finding("low", "Missing X-Content-Type-Options",
                               "Expected value: nosniff."))

    # Clickjacking: X-Frame-Options or CSP frame-ancestors
    has_xfo = bool(headers.get("X-Frame-Options"))
    has_fa = bool(csp and re.search(r"frame-ancestors", csp, re.I))
    if not (has_xfo or has_fa):
        results.append(finding("low", "No clickjacking protection",
                               "Neither X-Frame-Options nor CSP frame-ancestors set."))

    if not headers.get("Referrer-Policy"):
        results.append(finding("low", "Missing Referrer-Policy",
                               "Referrer-Policy header not set."))

    if not headers.get("Permissions-Policy"):
        results.append(finding("info", "Missing Permissions-Policy",
                               "Permissions-Policy header not set."))

    # Information disclosure
    server = headers.get("Server", "")
    if re.search(r"\d", server):
        results.append(finding("low", "Server version disclosed", f"Server: {server}"))
    if headers.get("X-Powered-By"):
        results.append(finding("low", "X-Powered-By disclosed",
                               f"X-Powered-By: {headers.get('X-Powered-By')}"))
    return results


def check_cookies(final_url, headers):
    results = []
    is_https = final_url.lower().startswith("https://")
    for raw in headers.get_all("Set-Cookie") or []:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0]
        attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else "")
                 for p in parts[1:]}
        if is_https and "secure" not in attrs:
            results.append(finding("medium", f"Cookie '{name}' missing Secure",
                                   "Cookie can be sent over plain HTTP."))
        if "httponly" not in attrs:
            results.append(finding("low", f"Cookie '{name}' missing HttpOnly",
                                   "Readable by JavaScript (matters most for session cookies)."))
        samesite = attrs.get("samesite")
        if samesite is None:
            results.append(finding("low", f"Cookie '{name}' missing SameSite",
                                   "Browser default applies; set explicitly."))
        elif samesite.lower() == "none" and "secure" not in attrs:
            results.append(finding("medium", f"Cookie '{name}' SameSite=None without Secure",
                                   "Browsers reject or mishandle this combination."))
    return results


def scan(url, timeout, verify_tls):
    try:
        final_url, status, headers = fetch(url, timeout, verify_tls)
    except Exception as exc:  # network, TLS, DNS, timeout
        return {"url": url, "error": f"{type(exc).__name__}: {exc}", "findings": []}
    findings = check_headers(final_url, headers) + check_cookies(final_url, headers)
    findings.sort(key=lambda f: -SEVERITY[f["severity"]])
    return {"url": url, "final_url": final_url, "status": status, "findings": findings}


def to_markdown(results):
    lines = ["# Security header report", ""]
    for r in results:
        lines.append(f"## {r['url']}")
        if "error" in r:
            lines += [f"Error: {r['error']}", ""]
            continue
        lines.append(f"Final URL: {r['final_url']} (HTTP {r['status']})")
        lines.append("")
        if not r["findings"]:
            lines += ["No findings.", ""]
            continue
        lines += ["| Severity | Finding | Detail |", "|---|---|---|"]
        for f in r["findings"]:
            lines.append(f"| {f['severity']} | {f['title']} | {f['detail']} |")
        lines.append("")
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description="HTTP security header and cookie checker.")
    p.add_argument("urls", nargs="*", help="URLs to check")
    p.add_argument("-f", "--file", help="file with one URL per line")
    p.add_argument("--format", choices=["json", "markdown"], default="json")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--insecure", action="store_true",
                   help="skip TLS verification (lab use only)")
    p.add_argument("--fail-on", choices=["low", "medium", "high"],
                   help="exit with code 1 if any finding is at or above this severity")
    args = p.parse_args()

    urls = list(args.urls)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            urls += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    if not urls:
        p.error("provide at least one URL or --file")

    results = [scan(u, args.timeout, not args.insecure) for u in urls]
    print(json.dumps(results, indent=2) if args.format == "json" else to_markdown(results))

    if args.fail_on:
        # An unreachable target must not look like a clean scan in CI.
        if any("error" in r for r in results):
            return 2
        limit = SEVERITY[args.fail_on]
        if any(SEVERITY[f["severity"]] >= limit for r in results for f in r["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
