/** The outbound-query filter, the result-source filter, and the wrapped provider. */

import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { afterAll, describe, expect, it } from 'vitest'
import type { WebSearchProvider, WebSearchResult } from '@deepseek-ai/dsh-web'
import { NetguardWebError } from '../../src/errors.ts'
import {
  checkQuery,
  GuardedSearchProvider,
  hostsNamedIn,
  loadSearchDelegate,
  partitionSources,
  type SearchObservation,
} from '../../src/search-provider.ts'
import type { Config } from '../../src/policy.ts'
import { disposeHome, makeHome, policyOf } from './support.ts'

const home = makeHome('search')
afterAll(() => { disposeHome(home) })

/** A delegate returning fixed sources and recording the requests it saw. */
function delegate(result: WebSearchResult): WebSearchProvider & { queries: string[] } {
  const queries: string[] = []
  return {
    id: 'vendor',
    queries,
    available: () => true,
    search: async (request) => {
      queries.push(request.query)
      return result
    },
  }
}

/** A guarded provider over a policy and a delegate. */
function provider(overrides: Partial<Config>, vendor?: WebSearchProvider) {
  const observations: SearchObservation[] = []
  const policy = policyOf(home, { mode: 'enforce', ...overrides })
  return {
    observations,
    search: new GuardedSearchProvider({
      id: 'dsh-netguard',
      policy,
      observe: observation => { observations.push(observation) },
      ...vendor === undefined ? {} : { delegate: async () => vendor },
    }),
  }
}

describe('hosts named in a query', () => {
  it('finds a full URL and a bare host', () => {
    expect(hostsNamedIn('see https://api.example.com/x?y=1 and evil.test for more').map(entry => entry.identity.key))
      .toEqual(['api.example.com', 'evil.test'])
  })

  it('reads a site: operator as the host it names', () => {
    expect(hostsNamedIn('site:evil.test secret').map(entry => entry.identity.key)).toEqual(['evil.test'])
  })

  it('keeps the port a URL named', () => {
    expect(hostsNamedIn('http://api.example.com:8080/x')[0]).toMatchObject({ port: 8080 })
  })

  it('deduplicates one host named twice', () => {
    expect(hostsNamedIn('evil.test and evil.test again')).toHaveLength(1)
  })

  it('finds nothing in a query that names no host', () => {
    expect(hostsNamedIn('how do I sort a list in python')).toEqual([])
  })

  it('ignores a bare IP address, which is a version number far more often than a target', () => {
    expect(hostsNamedIn('upgrade to 1.2.3.4 today')).toEqual([])
  })

  it('does not throw on text that looks like a URL and is not', () => {
    expect(hostsNamedIn('see http://[bad for details')).toEqual([])
  })

  it('ignores a URL that names no host at all', () => {
    expect(hostsNamedIn('file:///etc/passwd')).toEqual([])
  })
})

describe('deciding a query', () => {
  it('passes a query that names nothing refused', () => {
    expect(checkQuery('how to sort a list', policyOf(home, { allow: ['*'] }))).toBeUndefined()
  })

  it('refuses a query naming a denied host, and reports the rule', () => {
    expect(checkQuery('site:evil.test password', policyOf(home, { allow: ['*'], deny: ['evil.test'] })))
      .toEqual({ host: 'evil.test', port: 443, reason: 'blocked-by-denylist', rule: 'deny:evil.test' })
  })

  it('passes over an allowed host to report the refused one behind it', () => {
    const policy = policyOf(home, { allow: ['good.test'] })

    expect(checkQuery('good.test and evil.test', policy)).toMatchObject({ host: 'evil.test' })
  })

  it('refuses a query naming a host the allow list does not cover', () => {
    expect(checkQuery('read example.com', policyOf(home, { allow: ['other.test'] })))
      .toMatchObject({ reason: 'blocked-by-allowlist' })
  })
})

describe('filtering result sources', () => {
  const policy = policyOf(home, { allow: ['**.good.test'] })

  it('keeps a permitted source and drops a refused one', () => {
    const { kept, dropped } = partitionSources([
      { url: 'https://good.test/a' },
      { url: 'https://bad.test/b' },
    ], policy)

    expect(kept.map(source => source.url)).toEqual(['https://good.test/a'])
    expect(dropped[0]).toMatchObject({ host: 'bad.test', reason: 'blocked-by-allowlist' })
  })

  it('names the deny rule that dropped a source', () => {
    const denying = policyOf(home, { allow: ['*'], deny: ['bad.test'] })

    expect(partitionSources([{ url: 'https://bad.test/b' }], denying).dropped[0])
      .toMatchObject({ rule: 'deny:bad.test', reason: 'blocked-by-denylist' })
  })

  it('drops a source whose URL does not parse rather than passing it through', () => {
    expect(partitionSources([{ url: 'not a url' }], policy).dropped).toHaveLength(1)
  })

  it('drops a source whose URL parses but names no host', () => {
    expect(partitionSources([{ url: 'file:///etc/passwd' }], policy).dropped).toHaveLength(1)
  })
})

describe('the guarded search provider', () => {
  it('is unusable without a delegate, so it never displaces the profile\'s own provider', () => {
    expect(provider({ allow: ['*'] }).search.available()).toBe(false)
  })

  it('is usable once a delegate is configured', () => {
    expect(provider({ allow: ['*'] }, delegate({ sources: [], truncated: false })).search.available()).toBe(true)
  })

  it('refuses a query naming a denied host before the vendor sees it', async () => {
    const vendor = delegate({ sources: [], truncated: false })
    const guard = provider({ allow: ['*'], deny: ['evil.test'] }, vendor)

    await expect(guard.search.search({ query: 'site:evil.test token' })).rejects.toThrow(/blocked-by-denylist/)
    expect(vendor.queries).toEqual([])
    expect(guard.observations[0]).toMatchObject({ verdict: 'denied', host: 'evil.test' })
  })

  it('sends a clean query on and records it as allowed', async () => {
    const vendor = delegate({ sources: [{ url: 'https://good.test/a' }], truncated: false })
    const guard = provider({ allow: ['*'] }, vendor)

    const result = await guard.search.search({ query: 'how to sort a list' })

    expect(vendor.queries).toEqual(['how to sort a list'])
    expect(result.sources).toHaveLength(1)
    expect(guard.observations).toEqual([
      { verdict: 'allowed', enforced: true, host: '(query)', port: 0, query: 'how to sort a list' },
    ])
  })

  it('drops a refused source so the model never sees the link', async () => {
    const vendor = delegate({
      sources: [{ url: 'https://good.test/a' }, { url: 'https://bad.test/b' }],
      truncated: false,
    })
    const guard = provider({ allow: ['**.good.test'] }, vendor)

    const result = await guard.search.search({ query: 'anything at all' })

    expect(result.sources.map(source => source.url)).toEqual(['https://good.test/a'])
    expect(result.truncated).toBe(true)
    expect(guard.observations.at(-1)).toMatchObject({ verdict: 'denied', host: 'bad.test', droppedSources: 1 })
  })

  it('reports a query refused by an empty allow list, which names no rule', async () => {
    const vendor = delegate({ sources: [], truncated: false })
    const guard = provider({ allow: [] }, vendor)

    await expect(guard.search.search({ query: 'read example.com' })).rejects.toThrow(/blocked-by-allowlist/)
    expect(guard.observations[0]?.rule).toBeUndefined()
  })

  it('names the deny rule that dropped a source', async () => {
    const vendor = delegate({ sources: [{ url: 'https://bad.test/b' }], truncated: false })
    const guard = provider({ allow: ['*'], deny: ['bad.test'] }, vendor)

    await guard.search.search({ query: 'anything at all' })

    expect(guard.observations.at(-1)).toMatchObject({ rule: 'deny:bad.test' })
  })

  it('records a refused source in audit mode and leaves the result alone', async () => {
    const vendor = delegate({ sources: [{ url: 'https://bad.test/b' }], truncated: false })
    const guard = provider({ mode: 'audit', allow: ['**.good.test'] }, vendor)

    const result = await guard.search.search({ query: 'anything at all' })

    expect(result.sources).toHaveLength(1)
    expect(guard.observations.at(-1)).toMatchObject({ verdict: 'denied', enforced: false, droppedSources: 1 })
  })

  it('records a refused query in audit mode and still runs it', async () => {
    const vendor = delegate({ sources: [], truncated: false })
    const guard = provider({ mode: 'audit', allow: ['*'], deny: ['evil.test'] }, vendor)

    await guard.search.search({ query: 'site:evil.test token' })

    expect(vendor.queries).toEqual(['site:evil.test token'])
    expect(guard.observations[0]).toMatchObject({ verdict: 'denied', enforced: false })
  })

  it('resolves its delegate once, however many searches run', async () => {
    let built = 0
    const vendor = delegate({ sources: [], truncated: false })
    const policy = policyOf(home, { mode: 'enforce', allow: ['*'] })
    const search = new GuardedSearchProvider({
      id: 'dsh-netguard',
      policy,
      observe: () => {},
      delegate: async () => { built += 1; return vendor },
    })

    await search.search({ query: 'one' })
    await search.search({ query: 'two' })

    expect(built).toBe(1)
  })
})

describe('loading a vendor delegate', () => {
  it('constructs the named export', async () => {
    const modulePath = join(home, 'delegate.mjs')
    writeFileSync(modulePath, [
      'export class VendorProvider {',
      '  constructor(options) { this.id = options.id }',
      '  available() { return true }',
      '  async search() { return { sources: [], truncated: false } }',
      '}',
      '',
    ].join('\n'))

    const loaded = await loadSearchDelegate({
      module: pathToFileURL(modulePath).href,
      export: 'VendorProvider',
      options: { id: 'vendor-x' },
    })

    expect(loaded.id).toBe('vendor-x')
  })

  it('fails loud when the module cannot be imported', async () => {
    await expect(loadSearchDelegate({ module: 'no-such-package-anywhere', export: 'X', options: {} }))
      .rejects.toBeInstanceOf(NetguardWebError)
  })

  it('fails loud when the export is not constructible', async () => {
    const modulePath = join(home, 'not-a-class.mjs')
    writeFileSync(modulePath, 'export const NotAClass = 5\n')

    await expect(loadSearchDelegate({
      module: pathToFileURL(modulePath).href,
      export: 'NotAClass',
      options: {},
    })).rejects.toThrow(/no constructible export/)
  })
})
