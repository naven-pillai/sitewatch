# sitewatch

Uptime, TLS, domain-registration and crawlability monitoring for a list of
domains, run by GitHub Actions every 30 minutes. No account, no third-party
service, no cost.

```
python sitewatch.py                 # colored report in the terminal
python sitewatch.py --quick         # reachability + TLS only, no extra requests
python sitewatch.py --json          # machine-readable snapshot
python sitewatch.py --out docs      # write the dashboard's data files
```

`requests` is used when installed and the standard library is used when it
isn't, so the script runs on a clean machine. On macOS the command is `python3`.

## What it checks

| Check | Catches |
| ----- | ------- |
| **Reachability** | DNS failure, refused connection, timeout, 4xx, 5xx. |
| **TLS certificate** | Expiry countdown, untrusted chain, and whether the certificate actually covers the hostname. |
| **www / apex twin** | The variant people type but nobody tests. A site can be perfect on the apex and serving an expired certificate on `www`. |
| **Domain registration** | Days until the *domain* expires, via RDAP. Nothing auto-renews this, and it outlasts any outage. |
| **robots.txt** | A `Disallow: /` that blocks every crawler — the deploy accident that quietly costs weeks of search traffic. |
| **sitemap.xml** | Missing, unreachable, or pointing somewhere that no longer answers. |
| **Body content** | Optional. A page that returns 200 while rendering nothing useful. |

## Status levels

| Status  | Means |
| ------- | ----- |
| **Up**      | Answered 2xx/3xx, certificate valid and more than 21 days out, nothing else flagged. |
| **Warning** | Serving users, but something needs a look — a bot-block (401/403/429), a certificate inside 21 days, a domain inside 30 days, a broken www twin, a robots or sitemap problem, or a reply slower than 3 s. |
| **Down**    | DNS failed, the connection failed or timed out, the certificate is expired or untrusted, the domain registration lapsed, an expected string was missing, or the server returned 4xx/5xx. |

A 403 is deliberately *not* a failure. Cloudflare and similar front doors block
unfamiliar clients, and treating that as an outage produces false alarms.

Exit codes: `0` nothing to do, `1` warnings only, `2` action needed.

## The domain list

One entry per line. Bare domains get `https://` prepended; full URLs work, so
`https://kerja-ai.com/api/health` is valid if you would rather check a health
endpoint than a homepage — **which you should**, because a CDN will happily
serve a cached 200 homepage straight through a total database outage.

Options go after the domain:

```
kerja-ai.com                          # everything on
kerja-ai.com expect="Find AI jobs"    # body must contain this string
example.com noseo                     # skip robots.txt and sitemap
example.com nowww                     # skip the www/apex twin check
example.com nordap                    # skip domain registration lookup
```

RDAP has no coverage for `.my` — MYNIC publishes none — so those domains report
"not published" rather than a false all-clear. `.com` and `.asia` work.

## Alerting

One notification per incident, not one per check. A site down for a day sends
**3** notifications, not 48 — which is the difference between an alert you read
and an alert you filter to a folder.

- A new outage fails the run, and fails again every 12 hours while it continues.
- Recoveries and new warnings notify but do **not** fail the run.
- Steady state is silent.

GitHub emails you about failed scheduled runs. For something faster, add a
**`SITEWATCH_WEBHOOK_URL`** repository secret (Slack, Discord or Mattermost
incoming webhook) — the payload works with all three. Without the secret the
step is skipped.

Every run also writes a summary table to the Actions run page, so you can read
the result without opening logs.

## The dashboard

`docs/index.html` reads `status.json`, `history.json` and `events.json`, all
refreshed and committed by the workflow. To publish it:

**Settings → Pages → Source: Deploy from a branch → `main` / `/docs`**

It lands at `https://YOUR_USERNAME.github.io/sitewatch/`.

Locally:

```
python3 sitewatch.py --out docs
python3 -m http.server -d docs 8099     # then open http://localhost:8099
```

Opened straight from disk with no server, the page falls back to the snapshot
embedded in the HTML and labels itself `snapshot` instead of `live`.
Add `?theme=dark` or `?theme=light` to any URL to pin the theme.

## Data files

| File | Contents |
| ---- | -------- |
| `docs/status.json` | The latest snapshot. |
| `docs/history.json` | The last 500 runs, for the sparklines and availability figures. |
| `docs/events.json` | Status changes, plus which outages have already been notified. |
| `docs/rdap-cache.json` | Registration dates, refreshed every 12 hours so the registry isn't hammered. |

Removing a domain from `domains.txt` also drops it from `history.json` on the
next run, so the dashboard's median line always compares the same set of sites.
