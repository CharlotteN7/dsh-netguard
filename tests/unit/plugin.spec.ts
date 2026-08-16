/**
 * What `apply` wires up, over a real `ctx.web` and a stub tool registry.
 *
 * The assembled behaviour is proved by the E2E tests; these cover the
 * registrations, the composition check, and the tool-tier arm that mints the
 * identity a provider never receives.
 */

import { createServer, type Server } from 'node:http'
import { mkdirSync, writeFileSync } from 'node:fs'
import type { AddressInfo } from 'node:net'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import WebRuntime from '@deepseek-ai/dsh-web'
import type { WebFetchProvider, WebSearchProvider } from '@deepseek-ai/dsh-web'
import type { ToolExecution } from '@deepseek-ai/dsh-tools'
import type { Session, SessionEvent } from '@deepseek-ai/dsh-session'
import { apply, inject, name, readPackageVersion, VERSION } from '../../src/index.ts'
import type { Config } from '../../src/policy.ts'
import { disposeHome, dshOf, makeHome, spooled } from './support.ts'

const home = makeHome('plugin')
afterAll(() => { disposeHome(home) })

/** A guard registration, as `ctx.tools.guard()` receives it. */
type Guard = (exec: ToolExecution) => string | undefined

/** A stand-in fetch provider, for the ambiguity the composition check exists to catch. */
const shippedProvider: WebFetchProvider = {
  id: 'http',
  available: () => true,
  fetch: async () => { throw new Error('the composition check never calls a provider') },
}

let counter = 0

/** Mount the plugin over a real web seam and a stub tool registry. */
async function mount(overrides: Partial<Config> = {}, options: {
  readonly webConfig?: { fetchProvider?: string; searchProvider?: string }
  readonly alsoRegister?: WebFetchProvider
} = {}) {
  counter += 1
  const spoolPath = join(home, `spool-${String(counter)}.jsonl`)
  const ctx = new Context()
  await ctx.plugin(WebRuntime, options.webConfig ?? {})
  if (options.alsoRegister !== undefined) ctx.web.registerFetchProvider(options.alsoRegister)
  const guards: Guard[] = []
  const errors: string[] = []
  ctx.reflect.provide('tools', {
    guard(guard: Guard) {
      guards.push(guard)
      return () => {}
    },
  })
  ctx.logger.error = (message: unknown): void => { errors.push(String(message)) }

  const mounted = (): void => {
    apply(ctx, {
      spoolPath,
      hmacKey: { source: 'literal', value: 'k'.repeat(32) },
      fleet: { installUid: 'install-fixture' },
      ...overrides,
    }, { resolve: async () => [{ address: '127.0.0.1', family: 4 }] })
  }
  return {
    ctx,
    guards,
    errors,
    spoolPath,
    mounted,
    records: () => spooled(spoolPath),
    fetchProviders: () => (ctx.web as unknown as { fetchProviders: Map<string, WebFetchProvider> }).fetchProviders,
    searchProviders: () => (ctx.web as unknown as { searchProviders: Map<string, WebSearchProvider> }).searchProviders,
  }
}

/** One tool execution, as the guard receives it. */
function execution(toolName: string, args: unknown, extra: Record<string, unknown> = {}): ToolExecution {
  return {
    name: toolName,
    arguments: args,
    callId: 'call-1',
    rootCallId: 'call-1',
    ...extra,
  } as unknown as ToolExecution
}

describe('the plugin manifest', () => {
  it('declares its name and the services it needs before apply runs', () => {
    expect(name).toBe('dsh-netguard')
    expect(inject).toEqual(['web', 'tools'])
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/)
  })
})

describe('the composition check', () => {
  it('fails loud when another usable fetch provider is composed and nothing is pinned', async () => {
    const plugin = await mount({}, { alsoRegister: shippedProvider })

    expect(plugin.mounted).toThrow(/WEB_PROVIDER_AMBIGUOUS/)
  })

  it('mounts when the deployment pinned this package', async () => {
    const plugin = await mount({}, {
      alsoRegister: shippedProvider,
      webConfig: { fetchProvider: 'dsh-netguard' },
    })

    expect(plugin.mounted).not.toThrow()
  })

  it('fails loud when the pin names another provider', async () => {
    const plugin = await mount({}, { webConfig: { fetchProvider: 'http' } })

    expect(plugin.mounted).toThrow(/pinned to "http"/)
  })

  it('skips the check when the deployment turned the fetch provider off', async () => {
    const plugin = await mount({ fetch: { enabled: false } }, { alsoRegister: shippedProvider })

    expect(plugin.mounted).not.toThrow()
    expect(plugin.fetchProviders().has('dsh-netguard')).toBe(false)
  })

  it('checks the search seam only once a delegate makes this package usable', async () => {
    const withoutDelegate = await mount({}, { webConfig: { searchProvider: 'deepseek-official' } })
    expect(withoutDelegate.mounted).not.toThrow()

    const withDelegate = await mount(
      { search: { delegate: { module: 'x', export: 'X' } } },
      { webConfig: { searchProvider: 'deepseek-official' } },
    )
    expect(withDelegate.mounted).toThrow(/pinned to "deepseek-official"/)
  })
})

describe('the registrations', () => {
  it('registers one guard, one fetch provider and one search provider', async () => {
    const plugin = await mount()
    plugin.mounted()

    expect(plugin.guards).toHaveLength(1)
    expect(plugin.fetchProviders().get('dsh-netguard')?.available()).toBe(true)
    // Unusable without a delegate, so it never displaces a profile's own provider.
    expect(plugin.searchProviders().get('dsh-netguard')?.available()).toBe(false)
  })

  it('leaves the search arms out when the deployment turned them off', async () => {
    const plugin = await mount({ search: { enabled: false } })
    plugin.mounted()

    expect(plugin.searchProviders().has('dsh-netguard')).toBe(false)
    expect(plugin.guards[0]?.(execution('web_search', { query: 'site:evil.test x' }))).toBeUndefined()
  })
})

describe('the tool-tier guard', () => {
  it('abstains on a tool it does not govern', async () => {
    const plugin = await mount({ mode: 'enforce' })
    plugin.mounted()

    expect(plugin.guards[0]?.(execution('bash', { command: 'curl https://evil.test' }))).toBeUndefined()
    expect(plugin.records()).toEqual([])
  })

  it('abstains when the call carries no url or query', async () => {
    const plugin = await mount({ mode: 'enforce' })
    plugin.mounted()

    expect(plugin.guards[0]?.(execution('web_fetch', {}))).toBeUndefined()
    expect(plugin.guards[0]?.(execution('web_search', { query: 7 }))).toBeUndefined()
    expect(plugin.records()).toEqual([])
  })

  it('denies a refused host in enforce mode, with the reason the model can act on', async () => {
    const plugin = await mount({ mode: 'enforce', allow: ['good.test'] })
    plugin.mounted()

    const reason = plugin.guards[0]?.(execution('web_fetch', { url: 'https://evil.test/x' }))

    expect(reason).toContain('blocked-by-allowlist')
    expect(reason).toContain('evil.test')
    expect(plugin.records()).toHaveLength(1)
    expect(dshOf(plugin.records()[0]!)).toMatchObject({ kind: 'guard', verdict: 'denied', tool: 'web_fetch' })
  })

  it('denies nothing in audit mode, and leaves the record to the provider', async () => {
    const plugin = await mount({ mode: 'audit', allow: [] })
    plugin.mounted()

    expect(plugin.guards[0]?.(execution('web_fetch', { url: 'https://evil.test/x' }))).toBeUndefined()
    expect(plugin.records()).toEqual([])
  })

  it('records the decision itself when no fetch provider is mounted to make it', async () => {
    const plugin = await mount({ mode: 'audit', allow: [], fetch: { enabled: false } })
    plugin.mounted()

    expect(plugin.guards[0]?.(execution('web_fetch', { url: 'https://evil.test/x' }))).toBeUndefined()
    expect(dshOf(plugin.records()[0]!)).toMatchObject({ verdict: 'denied', enforced: false, kind: 'guard' })
  })

  it('records a permitted call itself when no provider will, and names no rule for an empty allow list', async () => {
    const permitted = await mount({ mode: 'audit', allow: ['*'], fetch: { enabled: false } })
    permitted.mounted()
    permitted.guards[0]?.(execution('web_fetch', { url: 'https://good.test/x' }))

    expect(dshOf(permitted.records()[0]!)).toMatchObject({ verdict: 'allowed', kind: 'guard' })
    expect(dshOf(permitted.records()[0]!)['reason']).toBeUndefined()
    expect(dshOf(permitted.records()[0]!)['rule']).toBe('allow:*')

    const refused = await mount({ mode: 'enforce', allow: [] })
    refused.mounted()
    refused.guards[0]?.(execution('web_fetch', { url: 'https://evil.test/x' }))

    expect(dshOf(refused.records()[0]!)['rule']).toBeUndefined()
  })

  it('names the deny rule that refused a search query', async () => {
    const plugin = await mount({ mode: 'enforce', allow: ['*'], deny: ['evil.test'] })
    plugin.mounted()

    plugin.guards[0]?.(execution('web_search', { query: 'site:evil.test token' }))

    expect(dshOf(plugin.records()[0]!)['rule']).toBe('deny:evil.test')
  })

  it('records a refused query itself even with a delegate, because the delegate never runs', async () => {
    const delegated = { search: { delegate: { module: 'x', export: 'X' } } }
    const enforcing = await mount(
      { mode: 'enforce', allow: ['*'], deny: ['evil.test'], ...delegated },
      { webConfig: { searchProvider: 'dsh-netguard' } },
    )
    enforcing.mounted()
    enforcing.guards[0]?.(execution('web_search', { query: 'site:evil.test x' }))

    expect(dshOf(enforcing.records()[0]!)).toMatchObject({ kind: 'guard', verdict: 'denied' })

    const auditing = await mount(
      { mode: 'audit', allow: ['*'], deny: ['evil.test'], ...delegated },
      { webConfig: { searchProvider: 'dsh-netguard' } },
    )
    auditing.mounted()
    auditing.guards[0]?.(execution('web_search', { query: 'site:evil.test x' }))

    // Audit mode runs the search, so the provider is the arm that records it.
    expect(auditing.records()).toEqual([])
  })

  it('writes nothing for a permitted call when the provider will record it', async () => {
    const plugin = await mount({ mode: 'enforce', allow: ['*'] })
    plugin.mounted()

    expect(plugin.guards[0]?.(execution('web_fetch', { url: 'https://good.test/x' }))).toBeUndefined()
    expect(plugin.records()).toEqual([])
  })

  it('abstains on a URL it cannot parse, leaving the tool its own argument error', async () => {
    const plugin = await mount({ mode: 'enforce' })
    plugin.mounted()

    expect(plugin.guards[0]?.(execution('web_fetch', { url: 'not a url' }))).toBeUndefined()
    expect(plugin.records()).toEqual([])
  })

  it('denies a search query naming a refused host', async () => {
    const plugin = await mount({ mode: 'enforce', allow: ['good.test'] })
    plugin.mounted()

    const reason = plugin.guards[0]?.(execution('web_search', { query: 'site:evil.test token' }))

    expect(reason).toContain('blocked-by-allowlist')
    expect(dshOf(plugin.records()[0]!)).toMatchObject({ kind: 'guard' })
    expect(plugin.records()[0]?.['dst_endpoint']).toMatchObject({ hostname: 'evil.test' })
  })

  it('records an allowed search when no delegate will record it, and never the query itself', async () => {
    const plugin = await mount({ mode: 'enforce', allow: ['*'] })
    plugin.mounted()

    expect(plugin.guards[0]?.(execution('web_search', { query: 'AKIAIOSFODNN7EXAMPLE leak' }))).toBeUndefined()

    const [record] = plugin.records()
    expect(JSON.stringify(record)).not.toContain('AKIAIOSFODNN7EXAMPLE')
    expect(dshOf(record!)).toMatchObject({ verdict: 'allowed', kind: 'guard', query_length: 25 })
  })

  it('labels a decision with the turn and step from the tool/call event', async () => {
    const plugin = await mount({ mode: 'enforce', allow: [] })
    plugin.mounted()
    plugin.ctx.emit('session/event', {} as Session, {
      type: 'tool/call',
      seq: 1,
      time: 0,
      data: { turn: 3, step: 5, callId: 'call-1', name: 'web_fetch', arguments: '{}' },
    } as SessionEvent)

    plugin.guards[0]?.(execution('web_fetch', { url: 'https://evil.test/' }, {
      agent: { session: { id: 'session-9' } },
    }))

    expect(dshOf(plugin.records()[0]!)).toMatchObject({ turn: 3, step: 5, session_id: 'session-9' })
  })

  it('forgets a call once its result lands', async () => {
    const plugin = await mount({ mode: 'enforce', allow: [] })
    plugin.mounted()
    const emit = (event: SessionEvent): void => { plugin.ctx.emit('session/event', {} as Session, event) }
    emit({ type: 'tool/call', seq: 1, time: 0, data: { turn: 3, step: 5, callId: 'call-1', name: 'web_fetch', arguments: '{}' } } as SessionEvent)
    emit({ type: 'tool/result', seq: 2, time: 0, data: { message: { source: { callId: 'call-1' } } } } as unknown as SessionEvent)
    emit({ type: 'user/message', seq: 3, time: 0, data: {} } as unknown as SessionEvent)

    plugin.guards[0]?.(execution('web_fetch', { url: 'https://evil.test/' }))

    expect(dshOf(plugin.records()[0]!)['turn']).toBeUndefined()
  })
})

describe('mounting without a test seam', () => {
  it('resolves names through the system resolver', async () => {
    const ctx = new Context()
    await ctx.plugin(WebRuntime, {})
    const guards: Guard[] = []
    ctx.reflect.provide('tools', { guard(guard: Guard) { guards.push(guard); return () => {} } })

    apply(ctx, {
      spoolPath: join(home, 'default-seam.jsonl'),
      hmacKey: { source: 'literal', value: 'k'.repeat(32) },
      fleet: { installUid: 'install-fixture' },
    })

    expect(guards).toHaveLength(1)
  })

  it('falls back to a placeholder version when there is no manifest beside the module', () => {
    expect(readPackageVersion(pathToFileURL(join(home, 'nowhere', 'index.js')).href)).toBe('0.0.0')
  })

  it('falls back to a placeholder version when the manifest names none', () => {
    mkdirSync(join(home, 'unversioned', 'lib'), { recursive: true })
    writeFileSync(join(home, 'unversioned', 'package.json'), '{"name":"x"}\n')

    expect(readPackageVersion(pathToFileURL(join(home, 'unversioned', 'lib', 'index.js')).href)).toBe('0.0.0')
  })
})

describe('the repo-local policy tier', () => {
  it('adds a deny pattern the workspace shipped', async () => {
    const policyFile = join(home, 'repo-policy.yml')
    writeFileSync(policyFile, "v: 1\naddDeny: ['evil.test']\nenforce: true\n")
    const plugin = await mount({ mode: 'audit', allow: ['*'], policyFile })
    plugin.mounted()

    expect(plugin.guards[0]?.(execution('web_fetch', { url: 'https://evil.test/' })))
      .toContain('blocked-by-denylist')
  })

  it('mounts with the policy intact when the named file is absent', async () => {
    const plugin = await mount({ mode: 'enforce', allow: [], policyFile: join(home, 'absent.yml') })
    plugin.mounted()

    expect(plugin.guards[0]?.(execution('web_fetch', { url: 'https://evil.test/' }))).toContain('dsh-netguard refused')
    expect(plugin.errors).toEqual([])
  })

  it('reports a malformed file on both the logger and stderr, then ignores it', async () => {
    const policyFile = join(home, 'malformed-policy.yml')
    writeFileSync(policyFile, "v: 1\nallow: ['*']\n")
    const written: string[] = []
    const spy = vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
      written.push(String(chunk))
      return true
    })
    const plugin = await mount({ mode: 'enforce', allow: [], policyFile })
    try {
      plugin.mounted()
    } finally {
      spy.mockRestore()
    }

    expect(plugin.errors[0]).toContain('ignoring the repo-local policy')
    expect(written.join('')).toContain('ignoring the repo-local policy')
    expect(plugin.guards[0]?.(execution('web_fetch', { url: 'https://evil.test/' }))).toContain('dsh-netguard refused')
  })
})

describe('a spool that cannot be written', () => {
  it('is reported without changing the verdict', async () => {
    const plugin = await mount({ mode: 'enforce', allow: [], spoolPath: home })
    const written: string[] = []
    const spy = vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
      written.push(String(chunk))
      return true
    })
    try {
      plugin.mounted()
      expect(plugin.guards[0]?.(execution('web_fetch', { url: 'https://evil.test/' }))).toContain('dsh-netguard refused')
    } finally {
      spy.mockRestore()
    }

    expect(plugin.errors.join('')).toContain('audit sink write failed')
    expect(written.join('')).toContain('audit sink write failed')
  })
})

describe('the registered providers, driven through the seam', () => {
  const servers: Server[] = []
  afterAll(async () => {
    await Promise.all(servers.map(async server => await new Promise<void>(resolve => server.close(() => { resolve() }))))
  })

  it('spools a record for a request the fetch provider made', async () => {
    const server = createServer((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/plain' })
      response.end('body')
    })
    servers.push(server)
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const port = (server.address() as AddressInfo).port
    const plugin = await mount({
      mode: 'enforce',
      allow: [`allowed.test:${String(port)}`],
      allowPrivateAddresses: ['127.0.0.1/32'],
    })
    plugin.mounted()
    const url = `http://allowed.test:${String(port)}/page`
    // The guard runs first in a real pipeline; it is what mints the join.
    plugin.guards[0]?.(execution('web_fetch', { url }, { agent: { session: { id: 'session-4' } } }))

    const result = await plugin.ctx.web.fetch({ url })

    expect(result.body.content).toBe('body')
    const records = plugin.records()
    expect(records).toHaveLength(2)
    expect(dshOf(records[1]!)).toMatchObject({ kind: 'fetch', verdict: 'allowed', tool: 'web_fetch' })
    expect((records[1]?.['metadata'] as Record<string, unknown>)['correlation_uid']).toBe('session-4:call-1')
    expect(records[1]?.['dst_endpoint']).toMatchObject({ ip: '127.0.0.1' })
  })

  it('spools a record for a search the delegate answered', async () => {
    const modulePath = join(home, 'plugin-delegate.mjs')
    writeFileSync(modulePath, [
      'export class VendorProvider {',
      '  constructor() { this.id = "vendor" }',
      '  available() { return true }',
      '  async search() { return { sources: [{ url: "https://bad.test/x" }], truncated: false } }',
      '}',
      '',
    ].join('\n'))
    const plugin = await mount({
      mode: 'enforce',
      allow: ['**.good.test'],
      search: { delegate: { module: pathToFileURL(modulePath).href, export: 'VendorProvider' } },
    }, { webConfig: { searchProvider: 'dsh-netguard' } })
    plugin.mounted()

    const result = await plugin.ctx.web.search({ query: 'a harmless question' })

    expect(result.sources).toEqual([])
    const kinds = plugin.records().map(record => dshOf(record)['kind'])
    expect(kinds).toEqual(['search', 'search'])
    expect(dshOf(plugin.records()[1]!)).toMatchObject({ verdict: 'denied', dropped_sources: 1 })
  })
})
