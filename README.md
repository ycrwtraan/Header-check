# header-check

Small, dependency-free Python tool that checks HTTP security headers and cookie flags and reports weak or missing ones. Output is JSON or Markdown, and it can fail a CI job when findings reach a chosen severity.

> Use only against systems you own or are explicitly authorized to test.
> Results are heuristics. Validate findings manually before reporting them.

## What it checks

| Area | Checks |
|---|---|
| Transport | `Strict-Transport-Security` presence and `max-age` (HTTPS only) |
| Content | `Content-Security-Policy` presence, `unsafe-inline` / `unsafe-eval` |
| Browser | `X-Content-Type-Options`, clickjacking (`X-Frame-Options` or CSP `frame-ancestors`), `Referrer-Policy`, `Permissions-Policy` |
| Disclosure | `Server` with version, `X-Powered-By` |
| Cookies | `Secure`, `HttpOnly`, `SameSite`, `SameSite=None` without `Secure` |

## Usage

```bash
python3 header_check.py https://example.com
python3 header_check.py -f urls.txt --format markdown
python3 header_check.py https://staging.example.com --fail-on medium
```

Requires Python 3.8+ and no third-party packages.

### Options

| Option | Meaning |
|---|---|
| `-f, --file` | File with one URL per line (`#` lines ignored) |
| `--format` | `json` (default) or `markdown` |
| `--timeout` | Request timeout in seconds (default 10) |
| `--insecure` | Skip TLS verification (lab use only) |
| `--fail-on` | Exit `1` if any finding is at or above `low`, `medium` or `high` |

### Exit codes

- `0` no findings at or above the threshold (or no threshold set)
- `1` findings at or above `--fail-on`
- `2` a target could not be reached while `--fail-on` is set, so an outage never looks like a clean scan

## CI example (GitHub Actions)

```yaml
- name: Check security headers
  run: python3 header_check.py https://staging.example.com --fail-on medium
```

## Design notes

- Uses `GET` and follows redirects; headers are evaluated on the final response.
- Reads each `Set-Cookie` header separately, since servers send several.
- Severity is a simple heuristic, not CVSS. Missing CSP or `Secure` on a cookie weighs more than missing `Referrer-Policy`.
- Limits: it does not render pages, so headers set only on specific routes or via JavaScript are not seen.
