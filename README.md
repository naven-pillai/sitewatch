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
A site is only called **slow** when it exceeds its threshold on *two consecutive*
checks. One sample either side of a fixed line makes a row flap between up and
warning, which is how a dashboard gets ignored. The health endpoints run with
`slow=6000` because a route invoked once every 30 minutes is always a cold
start, and a wake-up plus a fresh TLS handshake to Postgres sits near the
normal 3-second line without anything being wrong.

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
example.com slow=6000                 # raise the "slow" threshold, in ms
```

RDAP has no coverage for `.my` — MYNIC publishes none — so those domains report
"not published" rather than a false all-clear. `.com` and `.asia` work.

## Health endpoints

`/api/health` exists in each of the seven Next.js apps. It runs one real
Postgres read with the publishable/anon key (so RLS still applies), returns
**200** with `{"status":"ok"}` when the read path works and **503** when it
doesn't, and is never cached — a cached "ok" would keep reporting green through
an incident.

```json
{ "status": "ok", "service": "kerja-ai", "database": "ok",
  "latencyMs": 283, "checkedAt": "2026-09-01T01:56:41.018Z" }
```

The query is bounded by a 5-second `AbortSignal.timeout`, so a hung database
returns 503 instead of holding the request open.

The entries are present but commented out in `domains.txt` — uncomment each one
after that site deploys, or a 404 will be reported as an outage.

`techpartner.my` is a static site with no server runtime, so it has no health
endpoint; its homepage check already covers everything there is to check.

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

## Checking from Malaysia and Singapore

GitHub's runners live in the US and Europe, so their response times say nothing
about what a visitor in Kuala Lumpur experiences. `probe/` is a small function
that measures response time from wherever you deploy it, and the checker folds
its readings into each row.

It measures **latency and reachability only**. A certificate's expiry date and a
robots.txt's contents read identically from anywhere, so the main checker keeps
ownership of those rather than duplicating them.

It takes no target from the caller — the list comes from its own environment, so
there is no way to make it fetch an arbitrary URL. Requests need a bearer token,
and it fails closed if that token isn't configured.

### Deploying it to Singapore

1. Import this repo in Vercel with **Root Directory** set to `probe`. The region
   is pinned to `sin1` in `probe/vercel.json`.
2. Set two environment variables on that project:
   - `SITEWATCH_PROBE_TOKEN` — any long random string.
   - `SITEWATCH_TARGETS` — run `python3 sitewatch.py --print-targets` and paste.
3. In this repo's settings, add variable `SITEWATCH_PROBE_URL`
   (`https://<your-probe>.vercel.app/api/probe`) and secret `SITEWATCH_PROBE_TOKEN`
   with the same value as step 2.

Locally, or on a VPS somewhere Vercel has no region — Kuala Lumpur, say:

```
SITEWATCH_PROBE_TOKEN=... SITEWATCH_TARGETS="$(python3 sitewatch.py --print-targets)" \
  node probe/server.js
python3 sitewatch.py --probe sin1=http://localhost:8787/api/probe
```

If the probe's target list drifts out of step with `domains.txt`, the run says
which sites it stopped covering — silence would be the worse failure.

A probe that is down is a monitoring problem, not an outage: it's reported on
its own line and never changes a site's status. A site that answers here but
**not** from the probe is a real outage for that audience, and does warn.

## The schedule

GitHub's cron is not honoured on free accounts. A `*/30 * * * *` schedule was
measured firing **6 times in 15 hours** — gaps of 110 to 296 minutes, an average
of 184. An outage could sit unnoticed for most of a working day, which makes
"checked every 30 minutes" a claim the infrastructure does not keep.

`trigger/` is a Cloudflare Worker whose cron *is* honoured. It owns the schedule
and dispatches the workflow over the GitHub API; GitHub then only ever runs on
an explicit dispatch. Free, and it fires on time.

```
cd trigger
npx wrangler login
npx wrangler secret put GITHUB_TOKEN     # paste the PAT from below
npx wrangler deploy
```

The token is a **fine-grained** personal access token, scoped to this repository
only, with **Actions: Read and write** — nothing else. Create it at
github.com/settings/personal-access-tokens.

Watch it work with `npx wrangler tail`, or look for `workflow_dispatch` runs
arriving every 30 minutes in the Actions tab.

Optionally `npx wrangler secret put TRIGGER_TOKEN` to enable a manual endpoint;
without that secret the Worker's HTTP route returns 404 to everyone, so it never
becomes something strangers can trigger.

**Once the Worker is confirmed firing, delete the `schedule:` block from
`.github/workflows/sitewatch.yml`** — leaving both means GitHub's unreliable
cron adds duplicate runs on top of the Worker's reliable ones. Do it in that
order, or there will be a window with nothing running at all.

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
