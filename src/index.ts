/**
 * `dsh-netguard` — a host allowlist on the `web_fetch` and `web_search` tools,
 * checked at connect time, refused only under `mode: enforce`.
 *
 * Four registrations:
 *
 * 1. `ctx.web.registerFetchProvider()` — the guarded fetch provider. It
 *    replaces `web-fetch-http`, resolves the name once, vets the answer, and
 *    pins the socket to the address it vetted.
 * 2. `ctx.web.registerSearchProvider()` — the guarded search provider. It
 *    reports itself unusable unless a deployment configures a vendor delegate,
 *    so mounting this plugin never breaks a profile's existing search route.
 * 3. `ctx.tools.guard()` — the parse-time arm, registered **unscoped** so it
 *    covers every agent, every `run_code` sub-call and every subagent child. It
 *    denies a `web_fetch` to a refused host before the provider is reached, it
 *    denies a `web_search` whose query names a refused host, it records every
 *    call it cannot turn into a target at all, and it is where the tool-call
 *    identity a provider never receives is minted.
 * 4. `ctx.on('session/event')` — a read-only observer that keeps the
 *    `callId → { turn, step }` map. Nothing is ever appended to the session log.
 *
 * This plugin is not a containment boundary. It governs `web_fetch` and
 * `web_search`; it does not see one byte sent by `bash`, `run_code`, a terminal
 * session, an MCP server, or the model channel itself. See README.md.
 * @module dsh-netguard
 */

import { readFileSync } from 'node:fs'
import type { Context } from '@deepseek-ai/cordis'
import type { ToolExecution } from '@deepseek-ai/dsh-tools'
import type { Session, SessionEvent } from '@deepseek-ai/dsh-session'
import type {} from '@deepseek-ai/dsh-web'
import { UrlCardinality } from './cardinality.ts'
import { checkUrl } from './decide.ts'
import { CallCorrelator, TargetCorrelator, type CallIdentity } from './correlate.ts'
import { GuardedFetchProvider, type Resolver } from './fetch-provider.ts'
import { createEnvironment } from './ocsf.ts'
import { loadRepoPolicy, resolvePolicy, type Config, type RepoPolicy } from './policy.ts'
import { digest, digestQuery, digestUrl, HOST_MARKERS } from './privacy.ts'
import { assertPinnedProviderUsable, assertSelectable, readSeamState } from './mount.ts'
import { Recorder } from './recorder.ts'
import { argumentDenialMessage, denialMessage } from './reasons.ts'
import { checkQuery, GuardedSearchProvider, loadSearchDelegate } from './search-provider.ts'
import { HostMemory, SpoolSink } from './sink.ts'

export { Config } from './policy.ts'

/** Display metadata; labels the plugin in Cordis diagnostics. */
export const name = 'dsh-netguard'

/** Services required before `apply` runs. */
export const inject = ['web', 'tools']

/**
 * This package's own version, for `metadata.product.version`.
 * @param base - the module URL the manifest is resolved against.
 * @returns the manifest's version, or `0.0.0` when there is no readable manifest.
 */
export function readPackageVersion(base: string | URL): string {
  let manifest: string
  try {
    manifest = readFileSync(new URL('../package.json', base), 'utf8')
  } catch {
    // ENOENT only: a consumer that vendored the module without its manifest.
    // A record with an odd version beats a plugin that will not mount.
    return '0.0.0'
  }
  return (JSON.parse(manifest) as { version?: string }).version ?? '0.0.0'
}

/** Version reported in `metadata.product.version`. */
export const VERSION: string = readPackageVersion(import.meta.url)

/** The model-facing tool this package's fetch arm governs. */
const FETCH_TOOL = 'web_fetch'

/** The model-facing tool this package's search arm governs. */
const SEARCH_TOOL = 'web_search'

/**
 * Report a plugin fault on both the deployment's logger and `process.stderr`.
 *
 * `ctx.logger`'s default exporter is an in-memory ring buffer and no shipped
 * bundle mounts a console exporter, so a message that goes only to the logger
 * is invisible on a stock install.
 * @param ctx - the plugin's context, used for its logger.
 * @param message - the whole line to report; never carries a URL or a query.
 */
function report(ctx: Context, message: string): void {
  ctx.logger.error(message)
  process.stderr.write(`${message}\n`)
}

/**
 * Load the repo-local policy tier, if the deployment named one.
 *
 * A missing file is no policy at all, and a malformed one is reported and
 * ignored. The floor never depends on a workspace file being present or
 * well-formed: the recommended `policyFile` is workspace-relative, so failing
 * the mount would refuse to start `dsh` in every repository without one, and
 * would let a hostile repository disable the plugin by shipping a broken file.
 * @param ctx - the plugin's context, used only to report a bad file.
 * @param policyFile - the configured path, or `undefined` when none was named.
 * @returns the validated policy, or `undefined` when there is none to apply.
 */
export function loadConfiguredPolicy(ctx: Context, policyFile: string | undefined): RepoPolicy | undefined {
  if (policyFile === undefined) return undefined
  const load = loadRepoPolicy(policyFile)
  switch (load.kind) {
    case 'absent':
      return undefined
    case 'loaded':
      return load.policy
    case 'invalid':
      report(ctx, `dsh-netguard: ignoring the repo-local policy at ${policyFile}: ${load.problem}`)
      return undefined
    /* v8 ignore next 4 -- unreachable while `RepoPolicyLoad` stays closed; the arm exists so adding a variant fails the build. */
    default: {
      const unhandled: never = load
      throw new TypeError(`dsh-netguard: unhandled repo policy load ${JSON.stringify(unhandled)}`)
    }
  }
}

/** The identity a tool execution carries, as far as the tool tier can see it. */
function identityOf(exec: ToolExecution, calls: CallCorrelator): CallIdentity {
  const position = calls.lookup(String(exec.callId))
  const session = (exec.agent as { session?: { id?: unknown } } | undefined)?.session
  return {
    toolName: exec.name,
    callId: String(exec.callId),
    rootCallId: String(exec.rootCallId),
    ...session?.id === undefined ? {} : { sessionId: String(session.id) },
    ...position === undefined ? {} : { turn: position.turn, step: position.step },
  }
}

/** What a tool call supplied as one of its string arguments. */
export type ToolArgument =
  | { readonly kind: 'string'; readonly value: string }
  /** The key is missing or `undefined`: the call names no target at all. */
  | { readonly kind: 'absent' }
  /** Present, but not a string — an array, an object with a `toString`, a number, `null`. */
  | { readonly kind: 'other'; readonly type: string }

/**
 * Read one string argument of a tool call.
 *
 * Tool arguments are model-authored JSON, which is a wire boundary: the key can
 * hold any JSON value. A non-string one used to skip the guard entirely, which
 * is a hole exactly where a model that wants to avoid the guard would write.
 * @param exec - the tool execution the guard was handed.
 * @param name - the argument to read.
 * @returns the string, its absence, or the type that was there instead.
 */
export function stringArgument(exec: ToolExecution, name: string): ToolArgument {
  const args = exec.arguments as Record<string, unknown> | null | undefined
  const value = args?.[name]
  if (typeof value === 'string') return { kind: 'string', value }
  if (value === undefined) return { kind: 'absent' }
  if (value === null) return { kind: 'other', type: 'null' }
  return { kind: 'other', type: Array.isArray(value) ? 'array' : typeof value }
}

/** Options `apply` accepts beyond `Config`, so tests can drive name resolution. */
export interface ApplyOptions {
  /** Name resolution used by the guarded fetch provider. */
  readonly resolve?: Resolver
}

/**
 * Mount the plugin.
 * @param ctx - the plugin's context; every registration is undone on unload.
 * @param config - validated `cordis.yml` configuration.
 * @param options - the test seam for name resolution.
 * @throws Error when the composition would leave this plugin's providers unselectable.
 */
export function apply(ctx: Context, config: Config, options: ApplyOptions = {}): void {
  const onFailure = (error: unknown): void => { report(ctx, `dsh-netguard: audit sink write failed: ${String(error)}`) }
  const policy = resolvePolicy(config, loadConfiguredPolicy(ctx, config.policyFile), process.env, onFailure)
  if (policy.fetch.enabled) {
    assertSelectable('fetch', readSeamState(ctx.web, 'fetchProviders', 'fetchProviderId', policy.fetchProviderId), policy.fetchProviderId)
  }
  if (policy.searchEnabled) {
    const state = readSeamState(ctx.web, 'searchProviders', 'searchProviderId', policy.searchProviderId)
    // Without a delegate this package's search provider reports itself
    // unusable, so it cannot make the seam ambiguous — but a profile that
    // pinned it would then fail every search at call time instead of failing
    // here.
    if (policy.searchDelegate === undefined) assertPinnedProviderUsable('search', state, policy.searchProviderId)
    else assertSelectable('search', state, policy.searchProviderId)
  }

  const sink = new SpoolSink(policy.spoolPath, onFailure)
  const memory = new HostMemory(policy.hostMemoryPath, onFailure)
  const calls = new CallCorrelator()
  const targets = new TargetCorrelator()
  const cardinality = new UrlCardinality()
  const recorder = new Recorder({ env: createEnvironment(policy, VERSION), sink, memory, cardinality, targets })

  ctx.on('session/event', (_session: Session, event: SessionEvent) => {
    if (event.type === 'tool/call') {
      calls.note(String(event.data.callId), { turn: event.data.turn, step: event.data.step })
      return
    }
    if (event.type === 'tool/result') {
      calls.forget(String(event.data.message.source.callId))
    }
  })

  // Registered on a plain context so it applies globally: to every agent, every
  // `run_code` inner sub-call, and every subagent child. An agent-scoped guard
  // would miss exactly the child a prompt-injected agent would spawn.
  ctx.effect(() => ctx.tools.guard((exec) => {
    if (exec.name === FETCH_TOOL) return guardFetch(exec)
    if (exec.name === SEARCH_TOOL && policy.searchEnabled) return guardSearch(exec)
    return undefined
  }), 'dsh-netguard tool guard')

  if (policy.fetch.enabled) {
    ctx.effect(() => ctx.web.registerFetchProvider(new GuardedFetchProvider({
      id: policy.fetchProviderId,
      policy,
      observe: observation => { recorder.fetch(observation) },
      ...options.resolve === undefined ? {} : { resolve: options.resolve },
    })), 'dsh-netguard fetch provider')
  }

  if (policy.searchEnabled) {
    const delegate = policy.searchDelegate
    ctx.effect(() => ctx.web.registerSearchProvider(new GuardedSearchProvider({
      id: policy.searchProviderId,
      policy,
      observe: observation => { recorder.search(observation) },
      ...delegate === undefined ? {} : { delegate: async () => await loadSearchDelegate(delegate) },
    })), 'dsh-netguard search provider')
  }

  /**
   * The parse-time arm for `web_fetch`.
   *
   * It always mints the tool-call join the provider cannot see, and it always
   * produces a record: a `url` argument that is not a string, and one that is
   * not a URL, are recorded against a marker rather than skipped, because a
   * request the guard cannot decide is exactly what an audit lane must not
   * lose. It records a *policy* decision only when it is the arm that decided
   * the request: an enforced denial here means the provider never runs, and a
   * deployment that turned the provider off leaves this as the only arm there
   * is. Otherwise the provider owns the record, so the same request is not
   * spooled twice.
   */
  function guardFetch(exec: ToolExecution): string | undefined {
    const enforced = policy.mode === 'enforce'
    const argument = stringArgument(exec, 'url')
    // An absent argument names no target and opens no socket; the tool's own
    // schema is what reports it.
    if (argument.kind === 'absent') return undefined
    const identity = identityOf(exec, calls)
    if (argument.kind === 'other') {
      recorder.guard(
        { verdict: 'denied', enforced, reason: 'blocked-by-invalid-argument', host: HOST_MARKERS.nonString, port: 0 },
        identity,
        { hop: 0, url_type: argument.type },
      )
      if (!enforced) return undefined
      return argumentDenialMessage('blocked-by-invalid-argument', `the url argument is of type "${argument.type}", not a string`)
    }
    const raw = argument.value
    targets.note(raw, identity)
    const checked = checkUrl(raw, policy)
    if (checked.kind === 'invalid') {
      recorder.guard(
        { verdict: 'denied', enforced, reason: checked.reason, host: HOST_MARKERS.unparsedUrl, port: 0 },
        identity,
        { hop: 0, url_digest: digest(policy.hmacKey, raw), url_length: raw.length },
      )
      if (!enforced) return undefined
      return argumentDenialMessage(checked.reason, checked.detail)
    }
    targets.note(checked.target.url.toString(), identity)
    const denied = checked.decision.kind === 'deny'
    const guardOwnsRecord = !policy.fetch.enabled || (denied && enforced)
    if (guardOwnsRecord) {
      const url = digestUrl(policy.hmacKey, checked.target.url)
      recorder.guard(
        {
          verdict: denied ? 'denied' : 'allowed',
          enforced,
          ...checked.decision.kind === 'deny' ? { reason: checked.decision.reason } : {},
          ...checked.decision.rule === undefined ? {} : { rule: checked.decision.rule },
          host: checked.target.identity.key,
          port: checked.target.port,
          scheme: checked.target.url.protocol.replace(':', ''),
        },
        identity,
        { hop: 0, url_digest: url.digest, url_length: url.length, has_query: url.hasQuery },
        { countUrl: url.digest },
      )
    }
    if (!denied || !enforced) return undefined
    /* v8 ignore next -- `denied` narrows the decision to its deny arm; the guard keeps the compiler's narrowing local. */
    if (checked.decision.kind !== 'deny') return undefined
    return denialMessage(checked.decision.reason, checked.target.display, checked.decision.rule)
  }

  /**
   * The outbound-query arm for `web_search`.
   *
   * The guard owns the record whenever no vendor delegate is configured,
   * because then it is the only arm this package has on the search path.
   */
  function guardSearch(exec: ToolExecution): string | undefined {
    const enforced = policy.mode === 'enforce'
    const argument = stringArgument(exec, 'query')
    if (argument.kind === 'absent') return undefined
    const identity = identityOf(exec, calls)
    if (argument.kind === 'other') {
      recorder.guard(
        { verdict: 'denied', enforced, reason: 'blocked-by-invalid-argument', host: HOST_MARKERS.nonString, port: 0 },
        identity,
        { query_type: argument.type },
      )
      if (!enforced) return undefined
      return argumentDenialMessage('blocked-by-invalid-argument', `the query argument is of type "${argument.type}", not a string`)
    }
    const query = argument.value
    targets.note(query, identity)
    const refused = checkQuery(query, policy)
    if (policy.searchDelegate === undefined || (refused !== undefined && enforced)) {
      const digested = digestQuery(policy.hmacKey, query)
      recorder.guard(
        {
          verdict: refused === undefined ? 'allowed' : 'denied',
          enforced,
          ...refused === undefined ? {} : { reason: refused.reason },
          ...refused?.rule === undefined ? {} : { rule: refused.rule },
          host: refused?.host ?? HOST_MARKERS.query,
          port: refused?.port ?? 0,
        },
        identity,
        {
          query_digest: digested.digest,
          query_length: digested.length,
          ...refused?.mention === undefined ? {} : { host_mention: refused.mention },
        },
        { remember: refused?.mention !== 'bare' },
      )
    }
    if (refused === undefined || !enforced) return undefined
    return denialMessage(refused.reason, refused.host, refused.rule)
  }
}
