/**
 * The composition check, read off a real `WebRuntime` and then exercised
 * against every selection state it can report.
 */

import { describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import WebRuntime from '@deepseek-ai/dsh-web'
import type { WebFetchProvider } from '@deepseek-ai/dsh-web'
import { assertSelectable, readSeamState } from '../../src/mount.ts'

/** A fetch provider that reports the availability a test needs. */
function stubProvider(id: string, usable: boolean): WebFetchProvider {
  return {
    id,
    available: () => usable,
    fetch: async () => { throw new Error('the composition check never calls a provider') },
  }
}

/** A live web seam with the providers a test registers into it. */
async function seam(config: { fetchProvider?: string } = {}): Promise<Context> {
  const ctx = new Context()
  await ctx.plugin(WebRuntime, config)
  return ctx
}

describe('reading the live seam', () => {
  it('reports the pin the deployment configured', async () => {
    const ctx = await seam({ fetchProvider: 'dsh-netguard' })

    expect(readSeamState(ctx.web, 'fetchProviders', 'fetchProviderId', 'dsh-netguard'))
      .toEqual({ pin: 'dsh-netguard', usableOthers: [] })
  })

  it('reports another registered usable provider, and excludes our own', async () => {
    const ctx = await seam()
    ctx.web.registerFetchProvider(stubProvider('http', true))
    ctx.web.registerFetchProvider(stubProvider('dsh-netguard', true))

    expect(readSeamState(ctx.web, 'fetchProviders', 'fetchProviderId', 'dsh-netguard'))
      .toEqual({ pin: undefined, usableOthers: ['http'] })
  })

  it('ignores a registered provider that reports itself unusable', async () => {
    const ctx = await seam()
    ctx.web.registerFetchProvider(stubProvider('exa', false))

    expect(readSeamState(ctx.web, 'fetchProviders', 'fetchProviderId', 'dsh-netguard').usableOthers).toEqual([])
  })

  it('reports the registry as unreadable when the seam does not expose one', () => {
    expect(readSeamState({}, 'fetchProviders', 'fetchProviderId', 'dsh-netguard'))
      .toEqual({ pin: undefined, usableOthers: undefined })
  })

  it('treats an empty pin as no pin', () => {
    expect(readSeamState({ fetchProviderId: '' }, 'fetchProviders', 'fetchProviderId', 'x').pin).toBeUndefined()
  })
})

describe('failing the mount', () => {
  it('accepts a pin naming this package', () => {
    expect(() => assertSelectable('fetch', { pin: 'dsh-netguard', usableOthers: ['http'] }, 'dsh-netguard'))
      .not.toThrow()
  })

  it('accepts no pin when nothing else is usable', () => {
    expect(() => assertSelectable('fetch', { pin: undefined, usableOthers: [] }, 'dsh-netguard')).not.toThrow()
  })

  it('refuses a pin naming another provider, because this one would never be selected', () => {
    expect(() => assertSelectable('fetch', { pin: 'http', usableOthers: [] }, 'dsh-netguard'))
      .toThrow(/pinned to "http".*would never be selected/s)
  })

  it('refuses an unpinned composition that already has a usable provider', () => {
    expect(() => assertSelectable('fetch', { pin: undefined, usableOthers: ['http'] }, 'dsh-netguard'))
      .toThrow(/WEB_PROVIDER_AMBIGUOUS/)
  })

  it('names every conflicting provider', () => {
    expect(() => assertSelectable('fetch', { pin: undefined, usableOthers: ['http', 'other'] }, 'dsh-netguard'))
      .toThrow(/"http", "other" are already registered/)
  })

  it('refuses to guess when the registry cannot be read', () => {
    expect(() => assertSelectable('search', { pin: undefined, usableOthers: undefined }, 'dsh-netguard'))
      .toThrow(/does not expose its search provider registry/)
  })

  it('quotes a working composition in every message', () => {
    expect(() => assertSelectable('fetch', { pin: undefined, usableOthers: ['http'] }, 'dsh-netguard'))
      .toThrow(/fetchProvider: dsh-netguard/)
  })
})

describe('the seam behaviour the check is written against', () => {
  it('still refuses two usable fetch providers at call time', async () => {
    const ctx = await seam()
    ctx.web.registerFetchProvider(stubProvider('http', true))
    ctx.web.registerFetchProvider(stubProvider('dsh-netguard', true))

    await expect(ctx.web.fetch({ url: 'https://example.com/' }))
      .rejects.toMatchObject({ code: 'WEB_PROVIDER_AMBIGUOUS' })
  })

  it('selects the pinned provider even beside another usable one', async () => {
    const ctx = await seam({ fetchProvider: 'dsh-netguard' })
    ctx.web.registerFetchProvider(stubProvider('http', true))
    let called = false
    ctx.web.registerFetchProvider({
      id: 'dsh-netguard',
      available: () => true,
      fetch: async () => {
        called = true
        return { url: 'https://example.com/', statusCode: 200, body: { kind: 'text', content: '' }, truncated: false }
      },
    })

    await ctx.web.fetch({ url: 'https://example.com/' })

    expect(called).toBe(true)
  })
})
