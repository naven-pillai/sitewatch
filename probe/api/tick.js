// Reliable clock for sitewatch, running on Vercel Cron.
//
// GitHub deprioritises scheduled workflows on free accounts: a "*/30" cron was
// measured firing 6 times in 15 hours, gaps of 110-296 minutes. Vercel Cron on
// a paid plan fires on schedule, so it owns the cadence and GitHub only ever
// runs on an explicit dispatch.
//
// Vercel sends `Authorization: Bearer $CRON_SECRET` on cron invocations, so
// this route is closed to anyone who cannot present it.

const GITHUB_API = "https://api.github.com"

function authorized(req) {
  const secret = process.env.CRON_SECRET
  if (!secret) return false // fail closed when unconfigured
  const header = req.headers.authorization || ""
  return header.startsWith("Bearer ") && header.slice(7) === secret
}

async function dispatch() {
  const repo = process.env.SITEWATCH_REPO
  const workflow = process.env.SITEWATCH_WORKFLOW || "sitewatch.yml"
  const ref = process.env.SITEWATCH_REF || "main"

  if (!process.env.GITHUB_TOKEN) return { ok: false, status: 0, detail: "GITHUB_TOKEN is not set" }
  if (!repo) return { ok: false, status: 0, detail: "SITEWATCH_REPO is not set" }

  const res = await fetch(`${GITHUB_API}/repos/${repo}/actions/workflows/${workflow}/dispatches`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "sitewatch-tick",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ ref }),
  })

  if (res.status === 204) return { ok: true, status: 204, repo, workflow, ref }
  const detail = await res.text().catch(() => "")
  return { ok: false, status: res.status, detail: detail.slice(0, 300) }
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store, max-age=0")

  if (!authorized(req)) {
    return res.status(401).json({
      error: process.env.CRON_SECRET ? "bad token" : "not configured — set CRON_SECRET",
    })
  }

  let result
  try {
    result = await dispatch()
    // One retry covers a transient 5xx or rate limit. A 401/404 is a config
    // problem; retrying it just doubles the noise.
    if (!result.ok && (result.status >= 500 || result.status === 429)) {
      await new Promise((r) => setTimeout(r, 2000))
      result = { ...(await dispatch()), retried: true }
    }
  } catch (err) {
    result = { ok: false, status: 0, detail: err instanceof Error ? err.message : String(err) }
  }

  console.log(result.ok ? `dispatched ${result.repo}` : `dispatch FAILED ${result.status}: ${result.detail}`)
  return res.status(result.ok ? 200 : 502).json(result)
}
