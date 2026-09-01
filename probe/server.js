// Runs the same handler outside Vercel: `node server.js` on a VPS gives you a
// vantage point anywhere Vercel has no region — Kuala Lumpur, for instance.
//
//   SITEWATCH_PROBE_TOKEN=... SITEWATCH_TARGETS="a.com,b.com" node server.js
//
import { createServer } from 'node:http'
import handler from './api/probe.js'

const port = Number(process.env.PORT || 8787)

createServer(async (req, res) => {
  if (!req.url.startsWith('/api/probe')) {
    res.writeHead(404).end('not found')
    return
  }
  // Minimal shim for the two response helpers the handler uses.
  res.setHeader = res.setHeader.bind(res)
  res.status = (code) => {
    res.statusCode = code
    return res
  }
  res.json = (body) => {
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify(body))
    return res
  }
  try {
    await handler(req, res)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
}).listen(port, () => {
  console.log(`sitewatch probe listening on http://localhost:${port}/api/probe`)
})
