# sitewatch

Uptime and TLS-certificate monitoring for nine domains, run by GitHub Actions
every 30 minutes. No account, no third-party service, no cost.

```
python sitewatch.py                 # colored report in the terminal
python sitewatch.py --json          # machine-readable snapshot
python sitewatch.py --out docs      # write the dashboard's data files
```

`requests` is used when installed and the standard library is used when it
isn't, so the script runs on a clean machine.

## What counts as what

| Status  | Means |
| ------- | ----- |
| **Up**      | Answered with 2xx/3xx, certificate valid and more than 21 days from expiry. |
| **Warning** | Answered, but something needs a look — a bot-block (401/403/429), a certificate inside 21 days, or a reply slower than 3 s. |
| **Down**    | DNS failed, the connection failed or timed out, the certificate is expired or untrusted, or the server returned 4xx/5xx. |

A 403 is deliberately *not* a failure. Cloudflare and similar front doors block
unfamiliar clients, and treating that as an outage produces false alarms.

Exit codes: `0` all clear, `1` warnings only, `2` at least one site down.

## The dashboard

`docs/index.html` reads `docs/status.json` and `docs/history.json`, both
refreshed and committed by the workflow. To publish it:

**Settings → Pages → Source: Deploy from a branch → `main` / `/docs`**

It lands at `https://YOUR_USERNAME.github.io/sitewatch/`.

Locally:

```
python sitewatch.py --out docs
python -m http.server -d docs 8099     # then open http://localhost:8099
```

Opened straight from disk with no server, the page falls back to the snapshot
embedded in the HTML and labels itself `snapshot` instead of `live`.
Add `?theme=dark` or `?theme=light` to any URL to pin the theme.

## Alerting

The workflow fails the job when a site is down, and GitHub emails you when a
scheduled run fails. Failed checks also appear as annotations on the run.
Confirm **Settings → Notifications → Actions → Email** is on for your account.

## Adding a site

Add a line to `domains.txt`. Bare domains get `https://` prepended; full URLs
work too, so `https://kerja-ai.com/api/health` is a valid entry if you would
rather check a health endpoint than the homepage.

History is capped at the most recent 500 runs — about ten days.
