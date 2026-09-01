// Singapore vantage point for sitewatch.
//
// Only latency and reachability are location-dependent — a certificate's expiry
// date and a robots.txt's contents read the same from anywhere. So this probe
// measures response time only, and the main checker keeps ownership of
// everything else. That keeps the deployed surface small.
//
// It takes no target from the caller. The list comes from its own environment,
// so there is no way to make it fetch an arbitrary URL: no open proxy, no SSRF.

import { timingSafeEqual } from 'node:crypto'

const REQUEST_TIMEOUT_MS = 8000
const MAX_TARGETS = 40

const UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 sitewatch-probe/1.0'

function authorized(req) {
  const expected = process.env.SITEWATCH_PROBE_TOKEN
  if (!expected) return false // fail closed when unconfigured
  const header = req.headers.authorization || ''
  const given = header.startsWith('Bearer ') ? header.slice(7) : ''
  const a = Buffer.from(given)
  const b = Buffer.from(expected)
  // timingSafeEqual throws on length mismatch, so compare lengths first.
  return a.length === b.length && timingSafeEqual(a, b)
}

function targets() {
  return (process.env.SITEWATCH_TARGETS || '')
    .split(/[\s,]+/)
    .map((t) => t.trim())
    .filter(Boolean)
    .map((t) => (t.includes('://') ? t : `https://${t}`))
    .slice(0, MAX_TARGETS)
}

async function measure(url) {
  for (const method of ['HEAD', 'GET']) {
    const started = Date.now()
    try {
      const res = await fetch(url, {
        method,
        redirect: 'follow',
        headers: { 'User-Agent': UA, Accept: '*/*' },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      })
      const ms = Date.now() - started
      // A 4xx from HEAD often just means HEAD is unsupported — retry with GET.
      if (method === 'HEAD' && res.status >= 400 && res.status < 500) continue
      return { url, code: res.status, ms, error: null }
    } catch (err) {
      const ms = Date.now() - started
      if (method === 'GET') {
        return {
          url,
          code: null,
          ms,
          error: err instanceof Error ? (err.name === 'TimeoutError' ? 'timed out' : err.message) : 'failed',
        }
      }
    }
  }
  return { url, code: null, ms: null, error: 'failed' }
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0')

  if (!authorized(req)) {
    return res.status(401).json({
      error: process.env.SITEWATCH_PROBE_TOKEN
        ? 'bad token'
        : 'probe is not configured — set SITEWATCH_PROBE_TOKEN',
    })
  }

  const list = targets()
  if (!list.length) {
    return res.status(500).json({ error: 'no targets — set SITEWATCH_TARGETS' })
  }

  const started = Date.now()
  const results = await Promise.all(list.map(measure))

  return res.status(200).json({
    region: process.env.VERCEL_REGION || process.env.SITEWATCH_REGION || 'unknown',
    checkedAt: new Date().toISOString(),
    elapsedMs: Date.now() - started,
    results,
  })
}
