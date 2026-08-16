/**
 * The evidence bar from CONVENTIONS.md §5: a booted harness, this plugin
 * mounted as the profile's fetch provider, a mock model driving a real
 * `web_fetch`, and an assertion on what the model got back and what the plugin
 * spooled.
 *
 * The fixture server runs in the test process and listens on loopback, so the
 * policy has to open `127.0.0.1` explicitly — loopback is a refused address by
 * default, and the point of `allowPrivateAddresses` is that opening it is a
 * deliberate, named act.
 */

import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { dshOf, runAgent, type OcsfLine } from './harness.ts'

/** The body the fixture serves, and the marker the assertions look for. */
const BODY = 'NETGUARD_E2E_BODY'

let server: Server
let origin: string
let host: string

beforeAll(async () => {
  server = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/plain' })
    response.end(BODY)
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address() as AddressInfo
  host = `127.0.0.1:${String(port)}`
  origin = `http://${host}`
})

afterAll(async () => {
  await new Promise<void>(resolve => server.close(() => { resolve() }))
})

/**
 * The rows a profile needs for `web_fetch` to run through this plugin: the tool
 * has to be enabled (the base bundle ships `fetch: false`) and the seam has to
 * be pinned at this provider.
 */
const COMPOSITION = [
  '- id: tool-web',
  '  config:',
  '    fetch: true',
  '    searchTimeoutMs: 60000',
  '- id: web',
  '  config:',
  '    fetchProvider: dsh-netguard',
  '    searchProvider: deepseek-official',
].join('\n')

/** Run one agent that issues a single `web_fetch` for the fixture URL. */
async function fetchThrough(netguard: Record<string, unknown>) {
  return await runAgent({
    task: 'fetch the fixture page',
    // One request per entry: the model asks for the tool, then answers. The
    // session-title provider issues a third request, so the script carries a
    // spare success.
    sequence: ['tool_call_success', 'success', 'success'],
    toolName: 'web_fetch',
    toolArguments: JSON.stringify({ url: `${origin}/page?token=E2E_SECRET_QUERY` }),
    successText: 'done',
    extraProfilePatch: COMPOSITION,
    netguard,
  })
}

/** The rendered `tool/result` content of one run, as the model received it. */
function toolResultText(sessionLog: readonly Record<string, unknown>[]): string {
  return JSON.stringify(sessionLog.filter(row => row['type'] === 'tool/result'))
}

describe('a real agent run through the guarded fetch provider', () => {
  it('retrieves an allowed host and records the connection it opened', async () => {
    const result = await fetchThrough({
      mode: 'enforce',
      allow: [host],
      allowPrivateAddresses: ['127.0.0.1/32'],
    })

    expect(result.code, result.stderr).toBe(0)
    expect(toolResultText(result.sessionLog)).toContain(BODY)

    const records = result.ocsfRecords
    // Two decisions per hop: the URL against the host policy, then the
    // resolver's answer against the address table. Only the second one has an
    // address to report.
    expect(records).toHaveLength(2)
    expect(records[0]?.['dst_endpoint']).not.toHaveProperty('ip')
    const opened = records[1] as OcsfLine
    expect(opened.activity_id).toBe(1)
    expect(opened.class_uid).toBe(4001)
    expect(opened.category_uid).toBe(4)
    expect(opened.type_uid).toBe(400_101)
    expect(opened.metadata['profiles']).toEqual(['security_control', 'host'])
    expect(opened['dst_endpoint']).toMatchObject({ hostname: '127.0.0.1', ip: '127.0.0.1' })
    expect(dshOf(opened)).toMatchObject({ verdict: 'allowed', mode: 'enforce', enforced: true })

    // The join the whole package exists for: the record names the tool call
    // that opened the connection, using the forwarder's own key scheme.
    const withCall = records.find(record => dshOf(record)['call_id'] !== undefined) as OcsfLine
    expect(dshOf(withCall)['tool']).toBe('web_fetch')
    expect(String(withCall.metadata.correlation_uid))
      .toBe(`${String(dshOf(withCall)['session_id'])}:${String(dshOf(withCall)['call_id'])}`)

    // The SOC lane carries the host and the address, never the query string.
    expect(JSON.stringify(records)).not.toContain('E2E_SECRET_QUERY')
    expect(String(dshOf(opened)['url_digest'])).toMatch(/^hmac-sha256:/)

    // Nothing of ours is ever appended to the user's session log.
    expect(result.sessionLog.some(row => String(row['type']).startsWith('netguard'))).toBe(false)
  }, 180_000)

  it('refuses a host the allow list does not cover, with a reason the model receives', async () => {
    const result = await fetchThrough({ mode: 'enforce', allow: [] })

    expect(result.code, result.stderr).toBe(0)
    const text = toolResultText(result.sessionLog)
    expect(text).toContain('blocked-by-allowlist')
    expect(text).toContain('dsh-netguard refused this request')
    expect(text).not.toContain(BODY)

    const refused = result.ocsfRecords.find(record => record.activity_id === 5) as OcsfLine
    expect(refused.class_uid).toBe(4001)
    expect(refused.type_uid).toBe(400_105)
    expect(refused['action_id']).toBe(2)
    expect(refused['disposition_id']).toBe(2)
    expect(refused.severity_id).toBe(3)
    expect(dshOf(refused)).toMatchObject({ verdict: 'denied', enforced: true, reason: 'blocked-by-allowlist' })
  }, 180_000)

  it('records the same call and permits it in audit mode, which is the default', async () => {
    const result = await fetchThrough({ allow: [] })

    expect(result.code, result.stderr).toBe(0)
    expect(toolResultText(result.sessionLog)).toContain(BODY)

    const logged = result.ocsfRecords.find(record => dshOf(record)['verdict'] === 'denied') as OcsfLine
    expect(dshOf(logged)).toMatchObject({ mode: 'audit', verdict: 'denied', enforced: false })
    // Open and Allowed, because the connection was made; `disposition_id: 17`
    // (Logged) and `enforced: false` are what say the policy would have refused it.
    expect(logged.activity_id).toBe(1)
    expect(logged['action_id']).toBe(1)
    expect(logged['disposition_id']).toBe(17)
    expect(logged['is_alert']).toBe(true)
  }, 180_000)
})
