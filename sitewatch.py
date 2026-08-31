#!/usr/bin/env python3
"""
sitewatch — uptime + SSL expiry checker for a list of domains.

  python sitewatch.py                  colored report in the terminal
  python sitewatch.py --json           machine-readable snapshot on stdout
  python sitewatch.py --out docs       write docs/status.json + docs/history.json
  python sitewatch.py --no-fail        never exit non-zero (for CI write steps)

Exit codes: 0 = everything fine, 1 = warnings only, 2 = at least one site down.
Uses `requests` when installed, falls back to the stdlib so it runs anywhere.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
except ImportError:  # stdlib fallback so `python sitewatch.py` works bare
    requests = None
    import urllib.error
    import urllib.request

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 sitewatch/1.0"
)
HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# Codes that mean "the server is alive but is refusing this particular request"
# — a bot-blocking WAF, a login wall, rate limiting. The site is not down.
BLOCKED_CODES = {401, 403, 405, 406, 418, 429}

UP, WARN, DOWN = "up", "warn", "down"
HISTORY_LIMIT = 500          # ~10 days at one run every 30 minutes
SSL_WARN_DAYS = 21
SSL_CRIT_DAYS = 7
SLOW_MS = 3000


# --------------------------------------------------------------------------- #
# checks
# --------------------------------------------------------------------------- #
def normalize(entry: str) -> tuple[str, str]:
    """'kerja-ai.com' -> ('kerja-ai.com', 'https://kerja-ai.com')"""
    entry = entry.strip()
    url = entry if "://" in entry else f"https://{entry}"
    host = urlparse(url).hostname or entry
    return host, url


def check_http(url: str, timeout: float) -> dict:
    """HEAD first (cheap), then GET if the server dislikes HEAD."""
    result = {"code": None, "ms": None, "final_url": None, "error": None, "method": None}
    for method in ("HEAD", "GET"):
        start = time.perf_counter()
        try:
            if requests is not None:
                r = requests.request(
                    method, url, timeout=timeout, allow_redirects=True,
                    headers=HEADERS, stream=(method == "GET"),
                )
                code, final = r.status_code, r.url
                if method == "GET":
                    r.close()
            else:
                req = urllib.request.Request(url, headers=HEADERS, method=method)
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    code, final = r.status, r.url
            elapsed = int((time.perf_counter() - start) * 1000)
            result.update(code=code, ms=elapsed, final_url=final, method=method, error=None)
            # A 4xx from HEAD is often just "HEAD unsupported" — retry properly.
            if method == "HEAD" and code is not None and 400 <= code < 500:
                continue
            return result

        except Exception as exc:  # noqa: BLE001 — any failure is a failed check
            elapsed = int((time.perf_counter() - start) * 1000)
            code = getattr(getattr(exc, "response", None), "status_code", None) \
                or getattr(exc, "code", None)
            result.update(code=code, ms=elapsed, method=method, error=describe(exc))
            if code:  # an HTTP error response still proves the server answered
                return result
    return result


def describe(exc: Exception) -> str:
    name = type(exc).__name__
    if requests is None and isinstance(exc, urllib.error.URLError) \
            and not isinstance(exc, urllib.error.HTTPError):
        exc = exc.reason if isinstance(exc.reason, Exception) else exc
    if requests is not None:
        if isinstance(exc, requests.exceptions.SSLError):
            return "TLS handshake failed"
        if isinstance(exc, requests.exceptions.ConnectTimeout):
            return "connection timed out"
        if isinstance(exc, requests.exceptions.ReadTimeout):
            return "read timed out"
        if isinstance(exc, requests.exceptions.TooManyRedirects):
            return "redirect loop"
        if isinstance(exc, requests.exceptions.ConnectionError):
            text = str(exc)
            if "NameResolutionError" in text or "getaddrinfo" in text:
                return "DNS did not resolve"
            if "Connection refused" in text:
                return "connection refused"
            return "connection failed"
    if isinstance(exc, socket.gaierror):
        return "DNS did not resolve"
    if isinstance(exc, socket.timeout):
        return "connection timed out"
    if isinstance(exc, ssl.SSLError):
        return "TLS handshake failed"
    msg = str(exc).strip().split("\n")[0]
    return (msg[:110] or name)


def check_ssl(host: str, timeout: float, port: int = 443) -> dict:
    """Read the leaf certificate. Falls back to an unverified read so that an
    expired or mismatched cert still reports *why* it is bad."""
    out = {"days_left": None, "expires": None, "issuer": None, "valid": None, "error": None}

    def read(verify: bool):
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert()

    try:
        cert, out["valid"] = read(True), True
    except ssl.SSLCertVerificationError as exc:
        out["valid"], out["error"] = False, exc.verify_message or "certificate not trusted"
        try:
            cert = read(False)
        except Exception:  # noqa: BLE001
            return out
    except Exception as exc:  # noqa: BLE001
        out["error"] = describe(exc)
        return out

    not_after = cert.get("notAfter") if isinstance(cert, dict) else None
    if not_after:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        out["expires"] = expires.isoformat().replace("+00:00", "Z")
        out["days_left"] = (expires - datetime.now(timezone.utc)).days
    issuer = dict(x[0] for x in cert.get("issuer", ())) if isinstance(cert, dict) else {}
    out["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
    return out


def classify(http: dict, tls: dict) -> tuple[str, str]:
    """-> (status, human note)"""
    code = http["code"]

    if code is None:
        return DOWN, http["error"] or "unreachable"
    if code >= 500:
        return DOWN, f"server error {code}"
    if code in BLOCKED_CODES:
        return WARN, f"{code} — reachable, request blocked"
    if code >= 400:
        return DOWN, f"HTTP {code}"

    if tls["days_left"] is not None:
        if tls["days_left"] < 0:
            return DOWN, f"certificate expired {abs(tls['days_left'])}d ago"
        if tls["valid"] is False:
            return DOWN, tls["error"] or "certificate not trusted"
        if tls["days_left"] <= SSL_CRIT_DAYS:
            return WARN, f"certificate expires in {tls['days_left']}d"
        if tls["days_left"] <= SSL_WARN_DAYS:
            return WARN, f"certificate expires in {tls['days_left']}d"
    elif tls["error"]:
        return WARN, f"TLS: {tls['error']}"

    if http["ms"] and http["ms"] > SLOW_MS:
        return WARN, f"slow — {http['ms']} ms"
    return UP, "ok"


def check(entry: str, timeout: float) -> dict:
    host, url = normalize(entry)
    http = check_http(url, timeout)
    tls = check_ssl(host, timeout) if url.startswith("https") else \
        {"days_left": None, "expires": None, "issuer": None, "valid": None, "error": None}
    status, note = classify(http, tls)
    redirected = http["final_url"] and http["final_url"].rstrip("/") != url.rstrip("/")
    return {
        "domain": host,
        "url": url,
        "status": status,
        "note": note,
        "code": http["code"],
        "ms": http["ms"],
        "final_url": http["final_url"] if redirected else None,
        "ssl_days_left": tls["days_left"],
        "ssl_expires": tls["expires"],
        "ssl_issuer": tls["issuer"],
        "error": http["error"],
    }


def run(entries: list[str], timeout: float, workers: int) -> dict:
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda e: check(e, timeout), entries))
    results.sort(key=lambda r: ({DOWN: 0, WARN: 1, UP: 2}[r["status"]], r["domain"]))
    counts = {s: sum(1 for r in results if r["status"] == s) for s in (UP, WARN, DOWN)}
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "total": len(results),
        "counts": counts,
        "overall": DOWN if counts[DOWN] else (WARN if counts[WARN] else UP),
        "sites": results,
    }


# --------------------------------------------------------------------------- #
# terminal report
# --------------------------------------------------------------------------- #
class C:
    enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    @classmethod
    def _(cls, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if cls.enabled else text
    green = classmethod(lambda cls, t: cls._("32", t))
    red = classmethod(lambda cls, t: cls._("31", t))
    yellow = classmethod(lambda cls, t: cls._("33", t))
    dim = classmethod(lambda cls, t: cls._("2", t))
    bold = classmethod(lambda cls, t: cls._("1", t))


STYLE = {
    UP:   (C.green,  "UP  ", "●"),
    WARN: (C.yellow, "WARN", "●"),
    DOWN: (C.red,    "DOWN", "●"),
}


def report(snapshot: dict) -> None:
    width = max((len(s["domain"]) for s in snapshot["sites"]), default=10) + 2
    print()
    print(C.bold("  sitewatch") + C.dim(f"   {snapshot['generated_at']}"))
    print(C.dim("  " + "─" * (width + 46)))

    for s in snapshot["sites"]:
        color, label, dot = STYLE[s["status"]]
        code = str(s["code"] or "—").ljust(4)
        ms = f"{s['ms']} ms".rjust(8) if s["ms"] is not None else "—".rjust(8)
        if s["ssl_days_left"] is None:
            tls = C.dim("  ssl —  ")
        elif s["ssl_days_left"] < 0:
            tls = C.red("  ssl exp")
        else:
            days = f"{s['ssl_days_left']}d".rjust(5)
            paint = C.red if s["ssl_days_left"] <= SSL_CRIT_DAYS else (
                C.yellow if s["ssl_days_left"] <= SSL_WARN_DAYS else C.dim)
            tls = paint(f"  ssl {days}")
        note = "" if s["note"] == "ok" else C.dim(f"   {s['note']}")
        print(f"  {color(dot)} {color(label)}  {s['domain'].ljust(width)}"
              f"{C.dim(code)} {ms}{tls}{note}")

    c = snapshot["counts"]
    print(C.dim("  " + "─" * (width + 46)))
    summary = "  ".join([
        C.green(f"{c[UP]} up"),
        C.yellow(f"{c[WARN]} warning") if c[WARN] else C.dim("0 warnings"),
        C.red(f"{c[DOWN]} down") if c[DOWN] else C.dim("0 down"),
    ])
    tail = C.dim("of %d sites" % snapshot["total"])
    print(f"  {summary}   {tail}")
    print()


# --------------------------------------------------------------------------- #
# persistence for the dashboard
# --------------------------------------------------------------------------- #
def write_output(snapshot: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "status.json").write_text(json.dumps(snapshot, indent=2) + "\n")

    hist_path = out_dir / "history.json"
    history = {"runs": []}
    if hist_path.exists():
        try:
            loaded = json.loads(hist_path.read_text())
            if isinstance(loaded.get("runs"), list):
                history = loaded
        except (json.JSONDecodeError, OSError):
            pass  # corrupt history should never break a check run

    history["runs"].append({
        "t": snapshot["generated_at"],
        "sites": {
            s["domain"]: {"s": s["status"], "ms": s["ms"], "c": s["code"]}
            for s in snapshot["sites"]
        },
    })
    history["runs"] = history["runs"][-HISTORY_LIMIT:]

    # Drop domains that have left domains.txt. Otherwise the dashboard's median
    # line compares runs over different sets of sites, and removing a slow site
    # reads as everything suddenly getting faster.
    current = {s["domain"] for s in snapshot["sites"]}
    for run_entry in history["runs"]:
        run_entry["sites"] = {d: v for d, v in run_entry.get("sites", {}).items()
                              if d in current}
    history["runs"] = [r for r in history["runs"] if r["sites"]]
    hist_path.write_text(json.dumps(history, separators=(",", ":")) + "\n")


# --------------------------------------------------------------------------- #
def main() -> int:
    p = argparse.ArgumentParser(description="Uptime and SSL expiry checker.")
    p.add_argument("-f", "--file", default="domains.txt", help="domain list (default: domains.txt)")
    p.add_argument("--json", action="store_true", help="print the JSON snapshot instead of a report")
    p.add_argument("-o", "--out", metavar="DIR", help="write status.json + history.json into DIR")
    p.add_argument("-t", "--timeout", type=float, default=15.0, help="per-request timeout (default: 15)")
    p.add_argument("-w", "--workers", type=int, default=10, help="parallel checks (default: 10)")
    p.add_argument("--no-fail", action="store_true", help="always exit 0")
    args = p.parse_args()

    path = Path(args.file)
    if not path.is_absolute():
        path = Path(__file__).resolve().parent / path
    if not path.exists():
        print(f"sitewatch: no domain list at {path}", file=sys.stderr)
        return 3

    entries = [ln.strip() for ln in path.read_text().splitlines()]
    entries = [e for e in entries if e and not e.startswith("#")]
    if not entries:
        print(f"sitewatch: {path} has no domains in it", file=sys.stderr)
        return 3

    snapshot = run(entries, args.timeout, args.workers)

    if args.out:
        out = Path(args.out)
        if not out.is_absolute():
            out = Path(__file__).resolve().parent / out
        write_output(snapshot, out)

    if args.json:
        print(json.dumps(snapshot, indent=2))
    else:
        report(snapshot)

    if args.no_fail:
        return 0
    return 2 if snapshot["counts"][DOWN] else (1 if snapshot["counts"][WARN] else 0)


if __name__ == "__main__":
    sys.exit(main())
