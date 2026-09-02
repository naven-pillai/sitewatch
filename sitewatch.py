#!/usr/bin/env python3
"""
sitewatch — uptime, TLS, domain-registration and crawlability checks.

  python sitewatch.py                  colored report in the terminal
  python sitewatch.py --quick          reachability + TLS only, no extra requests
  python sitewatch.py --json           machine-readable snapshot on stdout
  python sitewatch.py --out docs       write the dashboard's data files
  python sitewatch.py --fail-on new    exit 2 only on a *change* for the worse

Exit codes: 0 = nothing to do, 1 = warnings only, 2 = action needed.
Uses `requests` when installed, falls back to the stdlib so it runs anywhere.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import shlex
import socket
import ssl
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:  # stdlib fallback so `python sitewatch.py` works bare
    requests = None
    import urllib.error
    import urllib.request

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 sitewatch/2.0"
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
RANK = {UP: 0, WARN: 1, DOWN: 2}

HISTORY_LIMIT = 500        # ~10 days at one run every 30 minutes
EVENT_LIMIT = 250          # state changes kept for the dashboard's log
SSL_WARN_DAYS = 21
SSL_CRIT_DAYS = 7
DOMAIN_WARN_DAYS = 30      # registration expiry is slower to fix than a cert
SLOW_MS = 3000
BODY_BYTES = 300_000
RDAP_TTL_HOURS = 12        # registration dates change about once a year
REALERT_HOURS = 12         # re-notify about an outage that is still going

# Suffixes where the registrable domain is three labels, not two.
MULTI_SUFFIXES = {
    "com.my", "net.my", "org.my", "edu.my", "gov.my", "com.sg", "net.sg",
    "org.sg", "edu.sg", "co.uk", "org.uk", "com.au", "co.id", "co.th",
}


# --------------------------------------------------------------------------- #
# domain list
# --------------------------------------------------------------------------- #
def parse_entry(line: str) -> dict:
    """
    'kerja-ai.com'                            -> all checks, defaults
    'kerja-ai.com expect="Find AI jobs"'      -> body must contain that string
    'x.com noseo nowww nordap'                -> opt out of individual checks
    """
    parts = shlex.split(line)
    target = parts[0]
    opts = {p.split("=", 1)[0]: (p.split("=", 1)[1] if "=" in p else True)
            for p in parts[1:]}

    url = target if "://" in target else f"https://{target}"
    parsed = urlparse(url)
    host = parsed.hostname or target
    path = parsed.path.rstrip("/")
    return {
        "url": url,
        "host": host,
        # Two entries can share a host (site root plus a health endpoint), so
        # the display name — which is also the history key — includes the path.
        "label": host + path,
        "expect": opts.get("expect") if isinstance(opts.get("expect"), str) else None,
        "seo": "noseo" not in opts,
        "www": "nowww" not in opts,
        "rdap": "nordap" not in opts,
        "slow_ms": int(opts["slow"]) if str(opts.get("slow", "")).isdigit() else SLOW_MS,
    }


def registrable(host: str) -> str:
    labels = host.lower().lstrip(".").split(".")
    if len(labels) > 2 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def counterpart_host(host: str) -> str | None:
    """www.example.com <-> example.com"""
    if host.startswith("www."):
        return host[4:]
    return f"www.{host}" if host.count(".") >= 1 else None


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #
def fetch(url: str, timeout: float, method: str = "GET", body: bool = False,
          extra_headers: dict | None = None) -> dict:
    """One request. -> {code, ms, final_url, text, error}"""
    out = {"code": None, "ms": None, "final_url": None, "text": None, "error": None}
    headers = {**HEADERS, **(extra_headers or {})}
    start = time.perf_counter()
    try:
        if requests is not None:
            r = requests.request(method, url, timeout=timeout, allow_redirects=True,
                                 headers=headers, stream=True)
            out["code"], out["final_url"] = r.status_code, r.url
            if body:
                chunks, total = [], 0
                for chunk in r.iter_content(16384, decode_unicode=False):
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= BODY_BYTES:
                        break
                out["text"] = b"".join(chunks).decode(r.encoding or "utf-8", "replace")
            r.close()
        else:
            req = urllib.request.Request(url, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                out["code"], out["final_url"] = r.status, r.url
                if body:
                    out["text"] = r.read(BODY_BYTES).decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 — any failure is a failed check
        out["code"] = (getattr(getattr(exc, "response", None), "status_code", None)
                       or getattr(exc, "code", None))
        out["error"] = describe(exc)
        if body and out["code"] and hasattr(exc, "read"):
            try:
                out["text"] = exc.read(BODY_BYTES).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                pass
    out["ms"] = int((time.perf_counter() - start) * 1000)
    return out


def describe(exc: Exception) -> str:
    if requests is None and isinstance(exc, urllib.error.URLError) \
            and not isinstance(exc, urllib.error.HTTPError):
        exc = exc.reason if isinstance(exc.reason, Exception) else exc
    if requests is not None:
        if isinstance(exc, requests.exceptions.SSLError):
            text = str(exc)
            return ("certificate has expired" if "expired" in text
                    else "hostname mismatch" if "match" in text
                    else "certificate not trusted")
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
    if isinstance(exc, ssl.SSLCertVerificationError):
        return (exc.verify_message or "certificate not trusted").lower()
    if isinstance(exc, socket.gaierror):
        return "DNS did not resolve"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "connection timed out"
    if isinstance(exc, ssl.SSLError):
        return "TLS handshake failed"
    return (str(exc).strip().split("\n")[0][:110] or type(exc).__name__)


# --------------------------------------------------------------------------- #
# individual checks
# --------------------------------------------------------------------------- #
def check_http(url: str, timeout: float, want_body: bool) -> dict:
    """HEAD first (cheap), then GET if the server dislikes HEAD or we need a body."""
    if not want_body:
        head = fetch(url, timeout, "HEAD")
        if head["code"] and not (400 <= head["code"] < 500):
            return head
        if head["code"] is None and head["error"]:
            return head          # transport failure — a GET will fail the same way
    return fetch(url, timeout, "GET", body=want_body)


def check_ssl(host: str, timeout: float, port: int = 443) -> dict:
    """Read the leaf certificate. Falls back to an unverified read so an expired
    or mismatched certificate still reports *why* it is bad."""
    out = {"days_left": None, "expires": None, "issuer": None, "valid": None,
           "error": None, "covers_host": None}

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
        out["valid"] = False
        out["error"] = exc.verify_message or "certificate not trusted"
        try:
            cert = read(False)
        except Exception:  # noqa: BLE001
            return out
    except Exception as exc:  # noqa: BLE001
        out["error"] = describe(exc)
        return out

    if not isinstance(cert, dict):
        return out
    if cert.get("notAfter"):
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z") \
            .replace(tzinfo=timezone.utc)
        out["expires"] = iso(expires)
        out["days_left"] = (expires - now()).days
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    out["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
    names = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    out["covers_host"] = any(
        n.lower() == host.lower()
        or (n.startswith("*.") and host.lower().endswith(n[1:].lower())
            and host.count(".") == n.count("."))
        for n in names) if names else None
    return out


def check_counterpart(host: str, timeout: float) -> dict | None:
    """The www/apex twin people actually type. A site can be perfect on one and
    broken on the other — most often an expired or missing certificate."""
    twin = counterpart_host(host)
    if not twin:
        return None
    r = fetch(f"https://{twin}", timeout, "HEAD")
    ok = bool(r["code"]) and r["code"] < 500 and not r["error"]
    return {"host": twin, "ok": ok, "code": r["code"],
            "error": None if ok else (r["error"] or f"HTTP {r['code']}")}


ROBOTS_BLOCK = re.compile(r"user-agent:\s*\*(.*?)(?=user-agent:|\Z)", re.I | re.S)


def check_seo(base: str, timeout: float) -> dict:
    """Guard the two files that silently destroy search traffic when they change:
    a robots.txt that blocks everyone, and a sitemap that has gone missing."""
    out = {"robots_code": None, "blocks_all": None,
           "sitemap_url": None, "sitemap_code": None, "sitemap_urls": None,
           "sitemap_is_index": None}

    robots = fetch(urljoin(base, "/robots.txt"), timeout, "GET", body=True)
    out["robots_code"] = robots["code"]
    text = robots["text"] or ""
    if robots["code"] == 200 and text:
        star = ROBOTS_BLOCK.search(text)
        if star:
            rules = [ln.strip() for ln in star.group(1).splitlines()]
            disallows = [ln.split(":", 1)[1].strip() for ln in rules
                         if ln.lower().startswith("disallow:")]
            allows = [ln.split(":", 1)[1].strip() for ln in rules
                      if ln.lower().startswith("allow:")]
            out["blocks_all"] = "/" in disallows and not allows
        sitemaps = re.findall(r"^\s*sitemap:\s*(\S+)", text, re.I | re.M)
        if sitemaps:
            out["sitemap_url"] = sitemaps[0]
    if not out["sitemap_url"]:
        out["sitemap_url"] = urljoin(base, "/sitemap.xml")

    sm = fetch(out["sitemap_url"], timeout, "GET", body=True)
    out["sitemap_code"] = sm["code"]
    if sm["code"] == 200 and sm["text"]:
        out["sitemap_is_index"] = "<sitemapindex" in sm["text"][:2000].lower()
        out["sitemap_urls"] = sm["text"].lower().count("<loc>")
    return out


def check_rdap(domain: str, timeout: float, cache: dict) -> dict:
    """Domain registration expiry. A lapsed registration outlasts any outage —
    and unlike a certificate, nothing renews it automatically."""
    hit = cache.get(domain)
    if hit and hit.get("checked_at"):
        try:
            age = now() - datetime.fromisoformat(hit["checked_at"].replace("Z", "+00:00"))
            if age < timedelta(hours=RDAP_TTL_HOURS):
                return {k: hit.get(k) for k in ("days_left", "expires", "registrar", "supported")}
        except ValueError:
            pass

    out = {"days_left": None, "expires": None, "registrar": None, "supported": True}
    r = fetch(f"https://rdap.org/domain/{domain}", timeout, "GET", body=True)
    if r["code"] == 404:
        out["supported"] = False           # ccTLDs such as .my publish no RDAP
    elif r["code"] == 200 and r["text"]:
        try:
            data = json.loads(r["text"])
            events = {e.get("eventAction"): e.get("eventDate")
                      for e in data.get("events", []) if isinstance(e, dict)}
            raw = events.get("expiration") or events.get("registrar expiration")
            if raw:
                expires = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                out["expires"] = iso(expires)
                out["days_left"] = (expires - now()).days
            for ent in data.get("entities", []):
                if "registrar" in (ent.get("roles") or []):
                    for item in (ent.get("vcardArray") or [None, []])[1]:
                        if item and item[0] == "fn":
                            out["registrar"] = item[3]
                    break
        except (json.JSONDecodeError, ValueError, IndexError, TypeError):
            pass
    else:
        return out                          # transient failure: don't poison the cache

    cache[domain] = {**out, "checked_at": iso(now())}
    return out


# --------------------------------------------------------------------------- #
# one site
# --------------------------------------------------------------------------- #
def classify(r: dict) -> tuple[str, list[str]]:
    """-> (status, issues worst-first). Empty issues means everything is fine."""
    down, warn = [], []
    code = r["code"]

    if code is None:
        down.append(r["error"] or "unreachable")
    elif code >= 500:
        down.append(f"server error {code}")
    elif code in BLOCKED_CODES:
        warn.append(f"HTTP {code} — reachable, request blocked")
    elif code >= 400:
        down.append(f"HTTP {code}")

    d = r["ssl_days_left"]
    if d is not None and d < 0:
        down.append(f"certificate expired {abs(d)} days ago")
    elif r["ssl_valid"] is False:
        down.append(r["ssl_error"] or "certificate not trusted")
    elif d is not None and d <= SSL_CRIT_DAYS:
        warn.append(f"certificate expires in {d} days")
    elif d is not None and d <= SSL_WARN_DAYS:
        warn.append(f"certificate expires in {d} days")

    dd = r["domain_days_left"]
    if dd is not None and dd < 0:
        down.append("domain registration expired")
    elif dd is not None and dd <= DOMAIN_WARN_DAYS:
        warn.append(f"domain registration expires in {dd} days")

    if r["expect_ok"] is False:
        down.append(f"page did not contain {r['expect']!r}")

    cp = r["counterpart"]
    if cp and not cp["ok"]:
        warn.append(f"{cp['host']} — {cp['error']}")

    if r["robots_blocks_all"]:
        warn.append("robots.txt blocks all crawlers")
    if r["sitemap_url"]:
        where = urlparse(r["sitemap_url"]).hostname or ""
        elsewhere = f" at {where}" if where and where.lstrip("www.") != r["domain"].lstrip("www.") else ""
        if r["sitemap_code"] is None:
            warn.append(f"sitemap unreachable{elsewhere}")
        elif r["sitemap_code"] != 200:
            warn.append(f"sitemap missing{elsewhere} (HTTP {r['sitemap_code']})")

    status = DOWN if down else (WARN if warn else UP)
    return status, down + warn


def check(entry: dict, timeout: float, quick: bool, rdap_cache: dict) -> dict:
    url, host = entry["url"], entry["host"]
    http = check_http(url, timeout, want_body=bool(entry["expect"]))
    tls = check_ssl(host, timeout) if url.startswith("https") else \
        {"days_left": None, "expires": None, "issuer": None, "valid": None,
         "error": None, "covers_host": None}

    # Secondary checks get a tighter budget: they add context, and none of them
    # should be able to hold a run open for the full primary timeout.
    aux = min(timeout, 8.0)
    seo = {} if quick or not entry["seo"] else check_seo(url, aux)
    cp = None if quick or not entry["www"] else check_counterpart(host, aux)
    rd = {} if quick or not entry["rdap"] else \
        check_rdap(registrable(host), aux, rdap_cache)

    expect_ok = None
    if entry["expect"] is not None and http["text"] is not None:
        expect_ok = entry["expect"].lower() in http["text"].lower()

    redirected = http["final_url"] and http["final_url"].rstrip("/") != url.rstrip("/")
    row = {
        "domain": entry["label"],
        "host": host,
        "url": url,
        "code": http["code"],
        "ms": http["ms"] if http["code"] else None,
        "final_url": http["final_url"] if redirected else None,
        "error": http["error"],
        "ssl_days_left": tls["days_left"],
        "ssl_expires": tls["expires"],
        "ssl_issuer": tls["issuer"],
        "ssl_valid": tls["valid"],
        "ssl_error": tls["error"],
        "expect": entry["expect"],
        "expect_ok": expect_ok,
        "counterpart": cp,
        "robots_code": seo.get("robots_code"),
        "robots_blocks_all": seo.get("blocks_all"),
        "sitemap_url": seo.get("sitemap_url"),
        "sitemap_code": seo.get("sitemap_code"),
        "sitemap_urls": seo.get("sitemap_urls"),
        "domain_days_left": rd.get("days_left"),
        "domain_expires": rd.get("expires"),
        "domain_registrar": rd.get("registrar"),
        "domain_rdap": rd.get("supported"),
        "slow_ms": entry["slow_ms"],
    }
    row["status"], row["issues"] = classify(row)
    row["note"] = row["issues"][0] if row["issues"] else "ok"
    return row


def run(entries: list[dict], timeout: float, workers: int, quick: bool,
        rdap_cache: dict) -> dict:
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda e: check(e, timeout, quick, rdap_cache), entries))
    results.sort(key=lambda r: (-RANK[r["status"]], r["domain"]))
    counts = {s: sum(1 for r in results if r["status"] == s) for s in (UP, WARN, DOWN)}
    return {
        "generated_at": iso(now()),
        "total": len(results),
        "counts": counts,
        "overall": DOWN if counts[DOWN] else (WARN if counts[WARN] else UP),
        "sites": results,
    }


def recount(snapshot: dict) -> None:
    """Re-derive ordering and totals after a post-pass has changed a status."""
    snapshot["sites"].sort(key=lambda r: (-RANK[r["status"]], r["domain"]))
    snapshot["counts"] = {s: sum(1 for r in snapshot["sites"] if r["status"] == s)
                          for s in (UP, WARN, DOWN)}
    snapshot["overall"] = (DOWN if snapshot["counts"][DOWN]
                           else WARN if snapshot["counts"][WARN] else UP)


def apply_slow(snapshot: dict, previous: dict | None) -> None:
    """Warn about slowness only when it persists across two checks.

    One sample either side of a fixed line makes a site flap between up and
    warning, which is how a dashboard gets ignored. Health endpoints are the
    worst case: invoked once every 30 minutes, they are always cold, so a
    wake-up plus a TLS handshake lands near the threshold every single time."""
    was_slow = {}
    for site in (previous or {}).get("sites", []):
        limit = site.get("slow_ms") or SLOW_MS
        was_slow[site["domain"]] = bool(site.get("ms") and site["ms"] > limit)

    for site in snapshot["sites"]:
        if site["status"] == DOWN or not site["ms"]:
            continue
        limit = site.get("slow_ms") or SLOW_MS
        if site["ms"] > limit and was_slow.get(site["domain"]):
            site["issues"].append(f"slow — {site['ms']} ms, and slow on the previous check")
            if site["status"] == UP:
                site["status"] = WARN
        site["note"] = site["issues"][0] if site["issues"] else "ok"
    recount(snapshot)


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# --------------------------------------------------------------------------- #
# remote vantage points
# --------------------------------------------------------------------------- #
def fetch_probe(name: str, url: str, token: str | None, timeout: float) -> dict:
    """Ask a probe deployed somewhere else — Singapore, say — how the sites look
    from there. Latency is the only thing that changes with location; the probe
    measures nothing else."""
    out = {"ok": False, "region": None, "error": None, "ms": None, "by_url": {}}
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    r = fetch(url, timeout, "GET", body=True, extra_headers=headers)
    out["ms"] = r["ms"]

    if r["code"] != 200 or not r["text"]:
        out["error"] = r["error"] or f"probe returned HTTP {r['code']}"
        return out
    try:
        data = json.loads(r["text"])
    except json.JSONDecodeError:
        out["error"] = "probe returned invalid JSON"
        return out

    out["region"] = data.get("region")
    for item in data.get("results", []):
        if isinstance(item, dict) and item.get("url"):
            out["by_url"][item["url"].rstrip("/")] = item
    out["ok"] = True
    return out


def apply_vantages(snapshot: dict, probes: dict) -> None:
    """Fold remote latency into each row. A site that answers here but not from
    Singapore is genuinely broken for the audience, so that earns a warning —
    but only when the probe itself is healthy, or one broken probe would paint
    every row yellow."""
    # The probe's target list lives in its own environment and can drift out of
    # step with domains.txt. Silently reporting nothing for the sites it forgot
    # would be the worst outcome, so track what it failed to cover.
    for probe in probes.values():
        probe["missing"] = []

    for site in snapshot["sites"]:
        seen = {}
        for name, probe in probes.items():
            if not probe["ok"]:
                continue
            hit = probe["by_url"].get(site["url"].rstrip("/"))
            if not hit:
                probe["missing"].append(site["domain"])
                continue
            seen[name] = {"ms": hit.get("ms"), "code": hit.get("code"),
                          "error": hit.get("error")}
            if hit.get("error") and site["status"] != DOWN:
                site["issues"].append(f"unreachable from {name} — {hit['error']}")
                site["status"] = WARN
        if seen:
            site["vantages"] = seen
        site["note"] = site["issues"][0] if site["issues"] else "ok"

    snapshot["probes"] = {
        name: {k: v for k, v in probe.items() if k != "by_url"}
        for name, probe in probes.items()
    }
    recount(snapshot)


# --------------------------------------------------------------------------- #
# state changes and alerting
# --------------------------------------------------------------------------- #
def transitions(previous: dict | None, snapshot: dict) -> list[dict]:
    if not previous:
        return []
    was = {s["domain"]: s for s in previous.get("sites", [])}
    events = []
    for site in snapshot["sites"]:
        before = was.get(site["domain"])
        if before and before["status"] != site["status"]:
            events.append({
                "t": snapshot["generated_at"],
                "domain": site["domain"],
                "from": before["status"],
                "to": site["status"],
                "note": site["note"],
            })
    return events


def alerts(snapshot: dict, events: list[dict], notified: dict) -> list[str]:
    """One notification per incident, not one per check.

    A site that has been down for a day should not send 48 identical emails —
    that is how alerting gets muted. Fires on a change, and once every
    REALERT_HOURS while an outage continues."""
    out, changed = [], {e["domain"]: e for e in events}
    for site in snapshot["sites"]:
        name, status = site["domain"], site["status"]
        if status == DOWN:
            last = notified.get(name)
            stale = True
            if last:
                try:
                    stale = (now() - datetime.fromisoformat(last.replace("Z", "+00:00"))) \
                        > timedelta(hours=REALERT_HOURS)
                except ValueError:
                    stale = True
            if name in changed or not last or stale:
                out.append(f"DOWN {name} — {site['note']}")
                notified[name] = snapshot["generated_at"]
        else:
            if name in notified:
                out.append(f"RECOVERED {name} — now {status}")
                notified.pop(name, None)
            elif name in changed and status == WARN:
                out.append(f"WARNING {name} — {site['note']}")
    return out


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


STYLE = {UP: (C.green, "UP  "), WARN: (C.yellow, "WARN"), DOWN: (C.red, "DOWN")}


def report(snapshot: dict, events: list[dict]) -> None:
    width = max((len(s["domain"]) for s in snapshot["sites"]), default=10) + 2
    rule = C.dim("  " + "─" * (width + 46))
    print()
    print(C.bold("  sitewatch") + C.dim(f"   {snapshot['generated_at']}"))
    print(rule)

    for s in snapshot["sites"]:
        color, label = STYLE[s["status"]]
        code = str(s["code"] or "—").ljust(4)
        ms = (f"{s['ms']} ms".rjust(8) if s["ms"] is not None else "—".rjust(8))
        d = s["ssl_days_left"]
        if d is None:
            tls = C.dim("  ssl —  ")
        elif d < 0:
            tls = C.red("  ssl exp")
        else:
            paint = C.red if d <= SSL_CRIT_DAYS else (C.yellow if d <= SSL_WARN_DAYS else C.dim)
            tls = paint(f"  ssl {f'{d}d'.rjust(5)}")
        remote = ""
        for name, v in (s.get("vantages") or {}).items():
            reading = f"{v['ms']} ms" if v.get("ms") is not None and not v.get("error") else "—"
            remote += C.dim(f"  {name} {reading.rjust(7)}")
        print(f"  {color('●')} {color(label)}  {s['domain'].ljust(width)}"
              f"{C.dim(code)} {ms}{tls}{remote}")
        for issue in s["issues"]:
            paint = C.red if s["status"] == DOWN else C.yellow
            print(f"    {paint('└')} {C.dim(issue)}")

    c = snapshot["counts"]
    print(rule)
    print("  " + "  ".join([
        C.green(f"{c[UP]} up"),
        C.yellow(f"{c[WARN]} warning") if c[WARN] else C.dim("0 warnings"),
        C.red(f"{c[DOWN]} down") if c[DOWN] else C.dim("0 down"),
    ]) + "   " + C.dim("of %d sites" % snapshot["total"]))

    for name, probe in (snapshot.get("probes") or {}).items():
        if not probe["ok"]:
            print(f"  {C.yellow('!')} probe {C.bold(name)} unavailable "
                  f"{C.dim('— ' + (probe['error'] or 'unknown'))}")
        elif probe.get("missing"):
            missing = ", ".join(probe["missing"])
            print(f"  {C.yellow('!')} probe {C.bold(name)} is not checking "
                  f"{C.dim(missing)}")
            print(f"    {C.dim('update its SITEWATCH_TARGETS — see --print-targets')}")

    if events:
        print()
        print(C.bold("  changed since the last check"))
        for e in events:
            paint = C.red if e["to"] == DOWN else (C.green if e["to"] == UP else C.yellow)
            print(f"    {paint('•')} {e['domain']} {C.dim(e['from'] + ' → ')}{paint(e['to'])}"
                  f"  {C.dim(e['note'])}")
    print()


# --------------------------------------------------------------------------- #
# persistence
# --------------------------------------------------------------------------- #
def load_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return default


def write_output(snapshot: dict, events: list[dict], notified: dict,
                 rdap_cache: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "status.json").write_text(json.dumps(snapshot, indent=2) + "\n")

    history = load_json(out_dir / "history.json", {"runs": []})
    if not isinstance(history.get("runs"), list):
        history = {"runs": []}
    history["runs"].append({
        "t": snapshot["generated_at"],
        "sites": {
            s["domain"]: {
                "s": s["status"], "ms": s["ms"], "c": s["code"],
                **({"v": {n: v["ms"] for n, v in s["vantages"].items()}}
                   if s.get("vantages") else {}),
            }
            for s in snapshot["sites"]
        },
    })
    history["runs"] = history["runs"][-HISTORY_LIMIT:]

    # Drop domains that have left domains.txt, so the dashboard's median line
    # compares runs over the same set of sites.
    current = {s["domain"] for s in snapshot["sites"]}
    for entry in history["runs"]:
        entry["sites"] = {d: v for d, v in entry.get("sites", {}).items() if d in current}
    history["runs"] = [r for r in history["runs"] if r["sites"]]
    (out_dir / "history.json").write_text(json.dumps(history, separators=(",", ":")) + "\n")

    log = load_json(out_dir / "events.json", {"events": [], "notified": {}})
    log["events"] = (log.get("events", []) + events)[-EVENT_LIMIT:]
    log["notified"] = notified
    (out_dir / "events.json").write_text(json.dumps(log, indent=2) + "\n")

    (out_dir / "rdap-cache.json").write_text(json.dumps(rdap_cache, indent=2) + "\n")


def step_summary(snapshot: dict, events: list[dict], fired: list[str]) -> None:
    """GitHub renders this on the run page, so the result is readable without
    opening logs."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    c, mark = snapshot["counts"], {UP: "🟢", WARN: "🟡", DOWN: "🔴"}
    lines = [f"## sitewatch — {c[UP]} up, {c[WARN]} warning, {c[DOWN]} down", ""]
    if fired:
        lines += ["**Alerts**", ""] + [f"- {a}" for a in fired] + [""]
    lines += ["| | Site | Response | Certificate | Notes |",
              "|---|---|---|---|---|"]
    for s in snapshot["sites"]:
        d = s["ssl_days_left"]
        lines.append(
            f"| {mark[s['status']]} | `{s['domain']}` "
            f"| {str(s['ms']) + ' ms' if s['ms'] else '—'} "
            f"| {str(d) + ' days' if d is not None else '—'} "
            f"| {'; '.join(s['issues']) or 'ok'} |")
    if events:
        lines += ["", "**Changed this run**", ""]
        lines += [f"- `{e['domain']}` {e['from']} → {e['to']} ({e['note']})" for e in events]
    with open(path, "a") as fh:
        fh.write("\n".join(lines) + "\n")


# --------------------------------------------------------------------------- #
def main() -> int:
    p = argparse.ArgumentParser(description="Uptime, TLS, domain and crawlability checks.")
    p.add_argument("-f", "--file", default="domains.txt", help="domain list (default: domains.txt)")
    p.add_argument("--json", action="store_true", help="print the JSON snapshot instead of a report")
    p.add_argument("-o", "--out", metavar="DIR", help="write the dashboard's data files into DIR")
    p.add_argument("-t", "--timeout", type=float, default=15.0, help="per-request timeout (default: 15)")
    p.add_argument("-w", "--workers", type=int, default=10, help="parallel checks (default: 10)")
    p.add_argument("--quick", action="store_true",
                   help="reachability and TLS only — skip robots, sitemap, www and RDAP")
    p.add_argument("--fail-on", choices=("any", "new", "never"), default="any",
                   help="exit 2 on any outage (default), only on a new one, or never")
    p.add_argument("--alert-payload", metavar="FILE",
                   help="write a webhook payload here when an alert fires")
    p.add_argument("--probe", action="append", default=[], metavar="NAME=URL",
                   help="a remote vantage point to fold in; repeatable "
                        "(token from $SITEWATCH_PROBE_TOKEN)")
    p.add_argument("--print-targets", action="store_true",
                   help="print the domain list as the probe's SITEWATCH_TARGETS value")
    p.add_argument("--no-fail", action="store_true", help="alias for --fail-on never")
    args = p.parse_args()

    here = Path(__file__).resolve().parent
    path = Path(args.file)
    if not path.is_absolute():
        path = here / path
    if not path.exists():
        print(f"sitewatch: no domain list at {path}", file=sys.stderr)
        return 3

    lines = [ln.strip() for ln in path.read_text().splitlines()]
    entries = [parse_entry(ln) for ln in lines if ln and not ln.startswith("#")]
    if not entries:
        print(f"sitewatch: {path} has no domains in it", file=sys.stderr)
        return 3

    out_dir = None
    if args.out:
        out_dir = Path(args.out)
        if not out_dir.is_absolute():
            out_dir = here / out_dir

    cache_path = (out_dir or here) / "rdap-cache.json"
    rdap_cache = load_json(cache_path, {})
    previous = load_json(out_dir / "status.json", None) if out_dir else None
    log = load_json(out_dir / "events.json", {"events": [], "notified": {}}) if out_dir \
        else {"events": [], "notified": {}}

    if args.print_targets:
        print(",".join(e["url"] for e in entries))
        return 0

    snapshot = run(entries, args.timeout, args.workers, args.quick, rdap_cache)
    apply_slow(snapshot, previous)

    probes = {}
    token = os.environ.get("SITEWATCH_PROBE_TOKEN")
    for spec in args.probe:
        if "=" not in spec:
            print(f"sitewatch: --probe needs NAME=URL, got {spec!r}", file=sys.stderr)
            return 3
        name, probe_url = spec.split("=", 1)
        probes[name] = fetch_probe(name, probe_url, token, args.timeout)
    if probes:
        apply_vantages(snapshot, probes)

    events = transitions(previous, snapshot)
    notified = dict(log.get("notified", {}))
    fired = alerts(snapshot, events, notified)

    if out_dir:
        write_output(snapshot, events, notified, rdap_cache, out_dir)
    step_summary(snapshot, events, fired)

    if args.alert_payload and fired:
        text = "sitewatch: " + "; ".join(fired)
        # "text" is what Slack and Mattermost read, "content" is Discord's.
        # "severity" lets CI fail on a real outage without failing on a recovery.
        Path(args.alert_payload).write_text(json.dumps({
            "text": text,
            "content": text,
            "alerts": fired,
            "severity": ("down" if any(a.startswith("DOWN") for a in fired)
                         else "warn" if any(a.startswith("WARNING") for a in fired)
                         else "info"),
        }, indent=2))

    if args.json:
        print(json.dumps(snapshot, indent=2))
    else:
        report(snapshot, events)
        for line in fired:
            print(f"  alert: {line}", file=sys.stderr)

    mode = "never" if args.no_fail else args.fail_on
    if mode == "never":
        return 0
    if mode == "new":
        return 2 if fired else 0
    return 2 if snapshot["counts"][DOWN] else (1 if snapshot["counts"][WARN] else 0)


if __name__ == "__main__":
    sys.exit(main())
