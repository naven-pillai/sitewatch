// Reliable clock for sitewatch.
//
// GitHub deprioritises scheduled workflows on free accounts heavily: a
// "*/30 * * * *" cron was firing roughly every 3 hours, with gaps up to 5.
// Cloudflare's cron triggers fire on time, so this Worker owns the schedule
// and GitHub only ever runs on an explicit dispatch.

const GITHUB_API = "https://api.github.com"

async function dispatch(env) {
  const repo = env.REPO
  const workflow = env.WORKFLOW || "sitewatch.yml"
  const ref = env.REF || "main"

  if (!env.GITHUB_TOKEN) throw new Error("GITHUB_TOKEN secret is not set")
  if (!repo) throw new Error("REPO var is not set")

  const res = await fetch(
    `${GITHUB_API}/repos/${repo}/actions/workflows/${workflow}/dispatches`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        // GitHub rejects requests without one.
        "User-Agent": "sitewatch-trigger",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ ref }),
    }
  )

  // A successful dispatch is 204 with an empty body.
  if (res.status === 204) return { ok: true, status: 204 }

  const detail = await res.text().catch(() => "")
  return { ok: false, status: res.status, detail: detail.slice(0, 300) }
}

async function dispatchWithRetry(env) {
  // Never throws. A misconfiguration should log a readable line, not crash the
  // invocation with an uncaught exception that says nothing useful.
  try {
    return await attempt(env)
  } catch (err) {
    return { ok: false, status: 0, detail: err instanceof Error ? err.message : String(err) }
  }
}

async function attempt(env) {
  const first = await dispatch(env)
  if (first.ok) return first
  // One retry covers a transient 5xx or a brief rate-limit; a 401/404 is a
  // configuration problem and retrying it just doubles the noise.
  if (first.status >= 500 || first.status === 429) {
    await new Promise((r) => setTimeout(r, 2000))
    const second = await dispatch(env)
    return second.ok ? second : { ...second, retried: true }
  }
  return first
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      dispatchWithRetry(env).then((result) => {
        if (result.ok) {
          console.log(`dispatched ${env.REPO} at ${new Date(event.scheduledTime).toISOString()}`)
        } else {
          // Surfaces in `wrangler tail` and Workers Logs.
          console.error(`dispatch FAILED ${result.status}: ${result.detail || ""}`)
        }
      })
    )
  },

  // Manual trigger, for testing. Closed unless TRIGGER_TOKEN is set and matches,
  // so this never becomes an endpoint anyone can hammer.
  async fetch(request, env) {
    const auth = request.headers.get("authorization") || ""
    const given = auth.startsWith("Bearer ") ? auth.slice(7) : ""
    if (!env.TRIGGER_TOKEN || given !== env.TRIGGER_TOKEN) {
      return new Response("not found", { status: 404 })
    }
    const result = await dispatchWithRetry(env)
    return Response.json(result, { status: result.ok ? 200 : 502 })
  },
}
