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
import { HOST_MARKERS } from './privacy.ts'
import { denialMessage, REASON_CODES, type DenialReason } from './reasons.ts'

/**
 * A URL written out in full, including its scheme.
 *
 * The scheme is length-bounded on purpose. Unbounded, every word boundary in a
 * long query is a start position that scans to the end of the text looking for
 * `://` and backtracks, which is one half of the quadratic cost this scan used
 * to have. No registered scheme is anywhere near 32 characters.
 */
const URL_IN_TEXT = /\b[a-z][a-z0-9+.-]{0,31}:\/\/[^\s'"<>)\]]+/gi

/**
 * A search operator whose argument is a host: `site:`, `inurl:`, `link:`.
 * Whatever follows one of these is meant as a destination, whether or not its
 * top-level label is a delegated domain.
 */
const HOST_OPERATOR_IN_TEXT = /\b(?:site|inurl|link)\s*:\s*([^\s'"<>)\]]+)/gi

/** Everything a bare hostname cannot contain; the query is split on it. */
const NOT_HOST_TEXT = /[^a-zA-Z0-9.-]+/

/** One label of a DNS name. */
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/

/** Longest DNS name, in characters. */
const MAX_HOST_LENGTH = 253

/** Longest DNS label, in characters. */
const MAX_LABEL_LENGTH = 63

/**
 * Top-level domains a *bare* token in prose is read as a hostname under.
 *
 * A dotted token is a hostname far less often than it is a filename: `index.js`,
 * `readme.md`, `setup.py` and `file.tar.gz` are ordinary words in an ordinary
 * developer question, and evaluating them against an egress allowlist refuses
 * the work rather than the attack. So a bare token has to end in a top-level
 * domain that is both delegated and not a common source-file or archive
 * extension. This is an approximation of the IANA root zone, exactly like the
 * public-suffix approximation in `hosts.ts`, and for the same reason: a data
 * file that goes stale does not belong in the trusted computing base of a
 * security control.
 *
 * The heuristic only decides *bare* tokens. A destination written as a URL, or
 * after `site:` / `inurl:` / `link:`, is read as a host whatever its top-level
 * label, so the spelling an exfiltration query actually uses is unaffected.
 */
const BARE_HOST_TLDS: ReadonlySet<string> = new Set([
  'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'name', 'pro', 'mobi', 'asia', 'eu',
  'app', 'dev', 'page', 'cloud', 'tech', 'online', 'site', 'website', 'store', 'shop', 'blog', 'news',
  'xyz', 'club', 'live', 'life', 'world', 'today', 'media', 'email', 'network', 'systems', 'solutions',
  'services', 'digital', 'agency', 'studio', 'software', 'codes', 'computer', 'host', 'hosting', 'run',
  'io', 'ai', 'co', 'me', 'tv', 'cc', 'gg', 'to', 'ly', 'fm', 'am', 'im',
  'us', 'uk', 'ca', 'mx', 'br', 'ar', 'cl', 'pe', 'de', 'fr', 'it', 'es', 'nl', 'be', 'ch', 'at',
  'se', 'no', 'dk', 'fi', 'is', 'ie', 'pt', 'gr', 'cz', 'sk', 'hu', 'ro', 'bg', 'hr', 'si', 'lt', 'lv',
  'ee', 'ua', 'ru', 'tr', 'il', 'ae', 'sa', 'za', 'ng', 'ke', 'eg', 'ma', 'in', 'cn', 'jp', 'kr', 'tw',
  'hk', 'sg', 'my', 'th', 'vn', 'id', 'ph', 'au', 'nz',
  // RFC 2606 and RFC 6761 reserve these for documentation and testing. They
  // resolve nowhere, and a query naming one is naming a host on purpose.
  'test', 'example', 'invalid', 'localhost',
])

/**
 * Dotted technology names that end in a delegated top-level domain and are
 * never a destination. `asp.net` is the one a developer types weekly.
 */
const NOT_A_BARE_HOST: ReadonlySet<string> = new Set(['asp.net', 'vb.net', 'ado.net'])

/** How a query named a host. */
export type HostMention =
  /** Inside a URL written out in full. */
  | 'url'
  /** After `site:`, `inurl:` or `link:`. */
  | 'operator'
  /** A bare dotted token in prose, read as a host only under {@link BARE_HOST_TLDS}. */
  | 'bare'

/** One host named inside a query, with the port the text implied. */
export interface NamedHost {
  readonly identity: HostIdentity
  readonly port: number
  readonly mention: HostMention
}

/**
 * The host one token names, or `undefined` when the token is not one.
 *
 * Every check is a bounded per-label test rather than one pattern over the
 * whole token: a nested-quantifier host pattern applied to an uncapped query is
 * where 300 KB of model output turned into 23 seconds of blocked event loop.
 * @param token - the candidate text, already split out of the query.
 * @param bare - true for a token found in prose, which needs a known top-level domain.
 * @returns the canonical identity, or `undefined`.
 */
function hostInToken(token: string, bare: boolean): HostIdentity | undefined {
  const text = token.toLowerCase().replace(/^\.+|\.+$/g, '')
  if (text.length === 0 || text.length > MAX_HOST_LENGTH) return undefined
  const labels = text.split('.')
  if (labels.length < 2) return undefined
  for (const label of labels) {
    if (label.length > MAX_LABEL_LENGTH || !HOST_LABEL.test(label)) return undefined
  }
  if (bare && (!BARE_HOST_TLDS.has(labels[labels.length - 1] as string) || NOT_A_BARE_HOST.has(text))) {
    return undefined
  }
  return identifyHost(text)
}

/** The host half of a `site:`-style operator argument, without its path or port. */
function operatorHost(argument: string): string {
  return argument.split(/[/?#:]/, 1)[0] as string
}

/**
 * Every host a query names, deduplicated by canonical host and port.
 * @param query - the outbound query text.
 * @returns the named hosts, in the order they appear.
 */
export function hostsNamedIn(query: string): readonly NamedHost[] {
  const found = new Map<string, NamedHost>()
  const remember = (identity: HostIdentity | undefined, port: number, mention: HostMention): void => {
    if (identity === undefined) return
    const key = `${identity.key}:${String(port)}`
    if (!found.has(key)) found.set(key, { identity, port, mention })
  }
  for (const match of query.matchAll(URL_IN_TEXT)) {
    try {
      const url = new URL(match[0])
      remember(identifyHost(url.hostname), effectivePort(url), 'url')
    } catch {
      // URL parse failure only: the passes below still see the text.
      continue
    }
  }
  for (const match of query.matchAll(HOST_OPERATOR_IN_TEXT)) {
    remember(hostInToken(operatorHost(match[1] as string), false), 443, 'operator')
  }
  for (const token of query.split(NOT_HOST_TEXT)) {
    remember(hostInToken(token, true), 443, 'bare')
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
  /** How the query named the host, when the decision is about a query's host. */
  readonly hostMention?: HostMention
  /** The outbound query, so the caller can digest it — never recorded verbatim. */
  readonly query: string
  /**
   * The vendor's own source URL, when `host` is a marker standing in for it.
   * The caller digests it; a vendor string is never recorded verbatim.
   */
  readonly sourceUrl?: string
  /** Sources dropped from a result, when the decision is about a result. */
  readonly droppedSources?: number
}

/** Notified once per search decision; must not throw. */
export type SearchObserver = (observation: SearchObservation) => void

/** Why one outbound query is refused. */
export interface QueryRefusal {
  readonly host: string
  readonly port: number
  readonly reason: DenialReason
  readonly rule?: string
  /** How the query named the host; absent when no host was read at all. */
  readonly mention?: HostMention
}

/**
 * Decide one outbound query against the host policy.
 *
 * A query past `search.maxQueryLength` is refused rather than scanned: the
 * hosts it names cannot be enumerated inside a budget, and a scan whose cost
 * the model controls runs synchronously inside `ctx.tools.guard()`, where it
 * blocks the agent loop, the UI and every timer.
 * @param query - the query the model asked for.
 * @param policy - the resolved policy.
 * @returns the first denied host and the rule that denied it, or `undefined`
 *   when nothing in the query is refused.
 */
export function checkQuery(query: string, policy: ResolvedPolicy): QueryRefusal | undefined {
  if (query.length > policy.searchMaxQueryLength) {
    return { host: HOST_MARKERS.query, port: 0, reason: 'blocked-by-query-length' }
  }
  for (const named of hostsNamedIn(query)) {
    // A host named in prose carries no path, and this filter is deciding
    // whether the host itself is one the policy tolerates: a path-scoped allow
    // entry counts as an allow for its host here, and the URL the model would
    // then fetch is decided against the path in full.
    const verdict = policy.hosts.evaluate(named.identity, named.port, undefined)
    if (verdict.kind === 'allow') continue
    return {
      host: named.identity.key,
      port: named.port,
      reason: verdict.reason,
      mention: named.mention,
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
      // against a host policy; it is dropped rather than passed through, and
      // the string itself never becomes the `host` a record carries verbatim.
      dropped.push({ source, host: HOST_MARKERS.unparsedSource, reason: 'blocked-by-invalid-url' })
      continue
    }
    const identity = identifyHost(url.hostname)
    if (identity === undefined) {
      dropped.push({ source, host: HOST_MARKERS.unparsedSource, reason: 'blocked-by-scheme' })
      continue
    }
    // A result source is a URL the model can hand straight to `web_fetch`, so
    // it is decided against the path the same way that fetch would be.
    const verdict = policy.hosts.evaluate(identity, effectivePort(url), url.pathname)
    if (verdict.kind === 'allow') {
      kept.push(source)
      continue
    }
    dropped.push({
      source,
      host: identity.key,
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
      this.#observe({ verdict: 'allowed', enforced, host: HOST_MARKERS.query, port: 0, query: request.query })
    } else {
      this.#observe({
        verdict: 'denied',
        enforced,
        reason: refused.reason,
        ...refused.rule === undefined ? {} : { rule: refused.rule },
        host: refused.host,
        port: refused.port,
        ...refused.mention === undefined ? {} : { hostMention: refused.mention },
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
        ...entry.host === HOST_MARKERS.unparsedSource ? { sourceUrl: entry.source.url } : {},
        droppedSources: 1,
      })
    }
    if (!enforced || dropped.length === 0) return result
    return { ...result, sources: kept, truncated: result.truncated || dropped.length > 0 }
  }
}
