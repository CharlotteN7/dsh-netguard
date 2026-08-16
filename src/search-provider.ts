/**
 * The search arms: the outbound-query filter, the result-source filter, and the
 * `WebSearchProvider` that wraps a vendor provider with both.
 *
 * What this can and cannot do is worth stating precisely, because the seam
 * gives a search provider much less than it gives a fetch provider.
 *
 * The query is a real exfiltration sink — the query string *is* the payload,
 * and it travels to the vendor before any result comes back. What this package
 * filters is the hosts named inside it: a query carrying a denied host is
 * refused, so `site:attacker.example <secret>` does not go out. A query that
 * names no host at all is not filtered, because there is nothing in it a host
 * allowlist can decide. **A plain-text secret in a plain-text query still
 * reaches the vendor**, and no host policy changes that.
 *
 * The vendor's own transport is not ours to govern: every shipped provider
 * calls bare global `fetch` against its own configured `baseURL`, and this
 * package does not patch `globalThis.fetch` (see ADR.md). What it does govern
 * is the *result*: a source whose host the policy denies is dropped before the
 * model sees it, so a search result cannot smuggle in a link the fetch
 * allowlist would refuse.
 * @module dsh-netguard/search-provider
 */

import type { WebSearchProvider, WebSearchRequest, WebSearchResult, WebSearchSource } from '@deepseek-ai/dsh-web'
import { identifyHost, type HostIdentity } from './address.ts'
import { effectivePort } from './decide.ts'
import { NetguardWebError } from './errors.ts'
import type { ResolvedPolicy, SearchDelegateConfig } from './policy.ts'
import { denialMessage, REASON_CODES, type DenialReason } from './reasons.ts'

/** A URL written out in full, including its scheme. */
const URL_IN_TEXT = /\b[a-z][a-z0-9+.-]*:\/\/[^\s'"<>)\]]+/gi

/**
 * A bare hostname: at least two dot-separated labels ending in an alphabetic
 * top-level label. It deliberately does not match a bare IP address — a
 * dotted quad inside a search query is far more often a version number or a
 * quoted address in prose than a target.
 */
const HOST_IN_TEXT = /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b/gi

/** One host named inside a query, with the port the text implied. */
export interface NamedHost {
  readonly identity: HostIdentity
  readonly port: number
}

/**
 * Every host a query names, deduplicated by canonical host and port.
 * @param query - the outbound query text.
 * @returns the named hosts, in the order they appear.
 */
export function hostsNamedIn(query: string): readonly NamedHost[] {
  const found = new Map<string, NamedHost>()
  const remember = (identity: HostIdentity | undefined, port: number): void => {
    if (identity === undefined) return
    const key = `${identity.key}:${String(port)}`
    if (!found.has(key)) found.set(key, { identity, port })
  }
  for (const match of query.matchAll(URL_IN_TEXT)) {
    try {
      const url = new URL(match[0])
      remember(identifyHost(url.hostname), effectivePort(url))
    } catch {
      // URL parse failure only: the bare-host pass below still sees the text.
      continue
    }
  }
  for (const match of query.matchAll(HOST_IN_TEXT)) {
    remember(identifyHost(match[0]), 443)
  }
  return [...found.values()]
}

/** What the search arms decided. */
export interface SearchObservation {
  readonly verdict: 'allowed' | 'denied'
  readonly enforced: boolean
  readonly reason?: DenialReason
  readonly rule?: string
  /** The host the decision is about; the query's own hosts, or a result source's. */
  readonly host: string
  readonly port: number
  /** The outbound query, so the caller can digest it — never recorded verbatim. */
  readonly query: string
  /** Sources dropped from a result, when the decision is about a result. */
  readonly droppedSources?: number
}

/** Notified once per search decision; must not throw. */
export type SearchObserver = (observation: SearchObservation) => void

/**
 * Decide one outbound query against the host policy.
 * @param query - the query the model asked for.
 * @param policy - the resolved policy.
 * @returns the first denied host and the rule that denied it, or `undefined`
 *   when nothing in the query is refused.
 */
export function checkQuery(
  query: string,
  policy: ResolvedPolicy,
): { readonly host: string; readonly port: number; readonly reason: DenialReason; readonly rule?: string } | undefined {
  for (const named of hostsNamedIn(query)) {
    const verdict = policy.hosts.evaluate(named.identity, named.port)
    if (verdict.kind === 'allow') continue
    return {
      host: named.identity.key,
      port: named.port,
      reason: verdict.reason,
      ...verdict.rule === undefined ? {} : { rule: verdict.rule },
    }
  }
  return undefined
}

/**
 * Split a result's sources into the ones the policy permits and the ones it
 * refuses.
 * @param sources - the vendor's sources.
 * @param policy - the resolved policy.
 * @returns the kept and dropped sources.
 */
export function partitionSources(
  sources: readonly WebSearchSource[],
  policy: ResolvedPolicy,
): { readonly kept: readonly WebSearchSource[]; readonly dropped: readonly { source: WebSearchSource; host: string; rule?: string; reason: DenialReason }[] } {
  const kept: WebSearchSource[] = []
  const dropped: { source: WebSearchSource; host: string; rule?: string; reason: DenialReason }[] = []
  for (const source of sources) {
    let url: URL
    try {
      url = new URL(source.url)
    } catch {
      // A vendor that returned something that is not a URL cannot be decided
      // against a host policy; it is dropped rather than passed through.
      dropped.push({ source, host: source.url, reason: 'blocked-by-allowlist' })
      continue
    }
    const identity = identifyHost(url.hostname)
    const verdict = identity === undefined
      ? ({ kind: 'deny', reason: 'blocked-by-allowlist' } as const)
      : policy.hosts.evaluate(identity, effectivePort(url))
    if (verdict.kind === 'allow') {
      kept.push(source)
      continue
    }
    dropped.push({
      source,
      host: identity?.key ?? url.hostname,
      reason: verdict.reason,
      ...verdict.rule === undefined ? {} : { rule: verdict.rule },
    })
  }
  return { kept, dropped }
}

/**
 * Import the vendor provider a deployment named.
 *
 * The module is resolved at first use rather than at mount, so a deployment
 * that configures no delegate never pays for the import and a broken specifier
 * fails the search rather than the whole profile boot.
 * @param delegate - the resolved delegate configuration.
 * @returns the constructed vendor provider.
 * @throws NetguardWebError when the module or the export cannot be used.
 */
export async function loadSearchDelegate(delegate: Required<SearchDelegateConfig>): Promise<WebSearchProvider> {
  let module: Record<string, unknown>
  try {
    module = await import(delegate.module) as Record<string, unknown>
  } catch (error: unknown) {
    throw new NetguardWebError(
      `dsh-netguard cannot import the search delegate "${delegate.module}": ${String(error)}`,
      'WEB_PROVIDER_UNAVAILABLE',
      { cause: error },
    )
  }
  const exported = module[delegate.export]
  if (typeof exported !== 'function') {
    throw new NetguardWebError(
      `dsh-netguard: "${delegate.module}" has no constructible export "${delegate.export}"`,
      'WEB_PROVIDER_UNAVAILABLE',
    )
  }
  const Provider = exported as new (options: Record<string, unknown>) => WebSearchProvider
  return new Provider(delegate.options)
}

/** Everything the guarded search provider needs beyond the policy. */
export interface GuardedSearchOptions {
  readonly id: string
  readonly policy: ResolvedPolicy
  readonly observe: SearchObserver
  /**
   * Resolves the vendor provider this one wraps. Absent leaves the provider
   * registered but unusable, so the seam keeps auto-selecting whatever vendor
   * plugin the profile already composes.
   */
  readonly delegate?: () => Promise<WebSearchProvider>
}

/** A `WebSearchProvider` that filters the outbound query and the returned sources. */
export class GuardedSearchProvider implements WebSearchProvider {
  readonly id: string
  readonly #policy: ResolvedPolicy
  readonly #observe: SearchObserver
  readonly #delegate: (() => Promise<WebSearchProvider>) | undefined
  #resolved: Promise<WebSearchProvider> | undefined

  /**
   * @param options - the provider id, the policy, the observer, and the delegate factory.
   */
  constructor(options: GuardedSearchOptions) {
    this.id = options.id
    this.#policy = options.policy
    this.#observe = options.observe
    this.#delegate = options.delegate
  }

  /**
   * Whether this provider can run a search.
   * @returns true only when a vendor delegate is configured; without one there
   *   is nothing to delegate to, and reporting `true` would make the seam
   *   select a provider that cannot answer.
   */
  available(): boolean {
    return this.#delegate !== undefined
  }

  /**
   * Filter the query, delegate the search, and filter the sources.
   * @param request - the seam's request.
   * @param signal - the caller's cancellation signal.
   * @returns the vendor's result with refused sources removed.
   * @throws NetguardWebError when the policy refuses the query in `enforce` mode.
   */
  async search(request: WebSearchRequest, signal?: AbortSignal): Promise<WebSearchResult> {
    /* v8 ignore next -- the seam only calls a provider it found usable, so `available()` has already been true. */
    if (this.#delegate === undefined) throw new NetguardWebError('dsh-netguard has no search delegate configured', 'WEB_PROVIDER_UNAVAILABLE')
    const enforced = this.#policy.mode === 'enforce'
    const refused = checkQuery(request.query, this.#policy)
    if (refused === undefined) {
      this.#observe({ verdict: 'allowed', enforced, host: '(query)', port: 0, query: request.query })
    } else {
      this.#observe({
        verdict: 'denied',
        enforced,
        reason: refused.reason,
        ...refused.rule === undefined ? {} : { rule: refused.rule },
        host: refused.host,
        port: refused.port,
        query: request.query,
      })
      if (enforced) {
        throw new NetguardWebError(
          denialMessage(refused.reason, refused.host, refused.rule),
          REASON_CODES[refused.reason],
        )
      }
    }

    this.#resolved ??= this.#delegate()
    const provider = await this.#resolved
    const result = await provider.search(request, signal)
    return this.#filterSources(result, request.query, enforced)
  }

  /** Drop refused sources, recording each one. */
  #filterSources(result: WebSearchResult, query: string, enforced: boolean): WebSearchResult {
    const { kept, dropped } = partitionSources(result.sources, this.#policy)
    for (const entry of dropped) {
      this.#observe({
        verdict: 'denied',
        enforced,
        reason: entry.reason,
        ...entry.rule === undefined ? {} : { rule: entry.rule },
        host: entry.host,
        port: 0,
        query,
        droppedSources: 1,
      })
    }
    if (!enforced || dropped.length === 0) return result
    return { ...result, sources: kept, truncated: result.truncated || dropped.length > 0 }
  }
}
