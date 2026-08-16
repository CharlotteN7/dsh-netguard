/**
 * The composition check that runs at `apply()`.
 *
 * `ctx.web` has no provider priority and no last-wins rule. A configured
 * `web.fetchProvider` (or `$DSH_WEB_FETCH_PROVIDER`) selects one; without it,
 * exactly one *usable* provider is required and two throw
 * `WEB_PROVIDER_AMBIGUOUS` at the first `web_fetch`
 * (`packages/web/web/src/index.ts:189`). `HttpFetchProvider.available()` is a
 * hardcoded `true`, so composing `web-fetch-http` beside this package and
 * pinning neither breaks `web_fetch` outright — at the first call, with an
 * error that names neither this plugin nor the fix.
 *
 * So the check runs at mount and fails loud there, per CONVENTIONS §2. It reads
 * two fields off the live `WebRuntime` instance: `fetchProviders` /
 * `searchProviders`, the registries, and `fetchProviderId` / `searchProviderId`,
 * the resolved pin (the seam resolves `config.fetchProvider ?? $DSH_WEB_FETCH_PROVIDER`
 * once in its constructor, so that one field already carries the environment
 * override). Both are `private` in TypeScript and ordinary own properties at
 * runtime. Reading them is a deliberate coupling to a specific harness version,
 * recorded in ADR.md; when a rename makes them unreadable the check reports
 * that it could not verify the composition rather than inventing a verdict.
 *
 * One order it cannot catch: a fetch provider composed *after* this plugin is
 * not in the registry yet when this runs. The shipped bundles compose
 * `@deepseek-ai/dsh-web` and its providers in the base layer and a plugin
 * bundle's rows come after, so the order that matters in practice is covered.
 * @module dsh-netguard/mount
 */

/** What could be read about one capability's provider selection. */
export interface SeamState {
  /** The resolved pin, or `undefined` when none is configured. */
  readonly pin: string | undefined
  /**
   * Other registered providers that report themselves usable, or `undefined`
   * when the registry could not be read at all.
   */
  readonly usableOthers: readonly string[] | undefined
}

/** The minimum a registered provider exposes. */
interface RegisteredProvider {
  readonly id: string
  available(): boolean
}

/**
 * Read one capability's selection state off the live `WebRuntime`.
 * @param web - the `ctx.web` service instance.
 * @param registryField - `fetchProviders` or `searchProviders`.
 * @param pinField - `fetchProviderId` or `searchProviderId`.
 * @param ourId - the id this package registers under, excluded from the others.
 * @returns what could be read; `undefined` fields mean "not readable".
 */
export function readSeamState(
  web: unknown,
  registryField: string,
  pinField: string,
  ourId: string,
): SeamState {
  const service = web as Record<string, unknown>
  const pinValue = service[pinField]
  const registry = service[registryField]
  const pin = typeof pinValue === 'string' && pinValue.length > 0 ? pinValue : undefined
  if (!(registry instanceof Map)) return { pin, usableOthers: undefined }
  const usableOthers: string[] = []
  for (const provider of (registry as Map<string, RegisteredProvider>).values()) {
    if (provider.id === ourId) continue
    // `available()` is the seam's own usability test and is documented as a
    // cheap local check that makes no network call.
    if (provider.available()) usableOthers.push(provider.id)
  }
  return { pin, usableOthers }
}

/**
 * The composition a profile needs, quoted in every failure message.
 *
 * This is the patch README.md prints, character for character: an operator who
 * reads one and pastes the other has to get the same profile either way.
 */
const REQUIRED_PATCH = [
  'Add this to the profile\'s cordis.patch.yml (a patch REPLACES a row\'s whole config,',
  'so restate every key the row needs):',
  '',
  '  - id: web',
  '    config:',
  '      fetchProvider: dsh-netguard',
  '      searchProvider: deepseek-official   # whatever your profile already uses',
  '',
  '  - id: tool-web',
  '    config:',
  '      fetch: true                          # the base bundle ships this off',
  '      searchTimeoutMs: 60000',
  '',
  '  # Only if your composition mounts the shipped provider; the base bundle does not.',
  '  - remove: [web-fetch-http]',
  '',
  '  - id: dsh-netguard',
  '    config:',
  '      mode: audit',
  '      allow: []',
  '      deny: []',
  '      spoolPath: /var/log/dsh/netguard.ocsf.jsonl',
].join('\n')

/**
 * Fail the mount when this package's provider could never be selected.
 *
 * @param capability - `fetch` or `search`, named in the message.
 * @param state - what {@link readSeamState} could read.
 * @param ourId - the id this package registers under.
 * @throws Error when the composition would leave `web_fetch` or `web_search`
 *   broken or this plugin bypassed.
 */
export function assertSelectable(capability: 'fetch' | 'search', state: SeamState, ourId: string): void {
  const key = capability === 'fetch' ? 'web.fetchProvider' : 'web.searchProvider'
  if (state.pin !== undefined && state.pin !== ourId) {
    throw new Error(
      `dsh-netguard: ${key} is pinned to "${state.pin}", so this plugin's "${ourId}" provider would never be`
      + ` selected and web_${capability} would run unguarded. Set ${key} to "${ourId}", or set`
      + ` ${capability}.enabled: false on the dsh-netguard row if this deployment does not want the guard.\n${REQUIRED_PATCH}`,
    )
  }
  if (state.pin === ourId) return
  if (state.usableOthers === undefined) {
    throw new Error(
      `dsh-netguard: this build of @deepseek-ai/dsh-web does not expose its ${capability} provider registry, so the`
      + ` composition cannot be verified. Pin ${key} to "${ourId}" explicitly.\n${REQUIRED_PATCH}`,
    )
  }
  if (state.usableOthers.length === 0) return
  throw new Error(
    `dsh-netguard: ${state.usableOthers.map(id => `"${id}"`).join(', ')} ${state.usableOthers.length > 1 ? 'are' : 'is'}`
    + ` already registered as a usable ${capability} provider and ${key} is not pinned. The seam refuses to choose`
    + ` between two usable providers (WEB_PROVIDER_AMBIGUOUS), so web_${capability} would fail at the first call.`
    + `\n${REQUIRED_PATCH}`,
  )
}

/**
 * Fail the mount when the profile pinned a provider this package registers
 * without configuring what that provider needs to answer.
 *
 * The guarded search provider reports itself unusable without a vendor
 * delegate, which is what keeps mounting this plugin from breaking a profile's
 * existing search route. A profile that pins it anyway composes cleanly and
 * then fails every `web_search` at call time, which is the half-working start
 * the mount check exists to prevent.
 * @param capability - `fetch` or `search`, named in the message.
 * @param state - what {@link readSeamState} could read.
 * @param ourId - the id this package registers under.
 * @throws Error when the pin names this package's unusable provider.
 */
export function assertPinnedProviderUsable(capability: 'fetch' | 'search', state: SeamState, ourId: string): void {
  if (state.pin !== ourId) return
  const key = capability === 'fetch' ? 'web.fetchProvider' : 'web.searchProvider'
  throw new Error(
    `dsh-netguard: ${key} is pinned to "${ourId}", but no ${capability}.delegate is configured, so this package's`
    + ` provider reports itself unusable and every web_${capability} would fail with WEB_PROVIDER_UNAVAILABLE.`
    + ` Configure ${capability}.delegate on the dsh-netguard row, or point ${key} at the vendor provider the`
    + ' profile already uses.',
  )
}
