/**
 * The guarded `WebFetchProvider`: connect-time enforcement of the host policy.
 *
 * It is built on `node:https`/`node:http` rather than global `fetch` for one
 * reason: global `fetch` ignores a `lookup` function in its `RequestInit`, and
 * without the `lookup` hook the check and the connect are two separate name
 * resolutions. A name that answers with a public address for the check and a
 * loopback address a millisecond later is the entire DNS-rebinding attack, and
 * a pre-check cannot close it. Here the resolver is called once, the answer is
 * vetted, and the socket is pinned to the exact address that was vetted;
 * `socket.remoteAddress` is verified on connect as the second half of the same
 * promise.
 *
 * `agent: false` is deliberate. A pooled agent may hand back a socket opened
 * earlier for the same hostname, to whatever address that earlier resolution
 * produced — which would make the pinning depend on connection reuse.
 *
 * Redirects are followed by this module, one hop at a time, with the whole
 * check re-run per hop, and a cross-origin hop is refused exactly as the
 * shipped `web-fetch-http` provider refuses it: each new origin has to be a new
 * tool call, and therefore a new policy decision.
 * @module dsh-netguard/fetch-provider
 */

import { request as httpRequest, type IncomingMessage, type RequestOptions } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { lookup as dnsLookup } from 'node:dns/promises'
import { TextDecoder } from 'node:util'
import type { LookupFunction } from 'node:net'
import type { WebFetchProvider, WebFetchRequest, WebFetchResult } from '@deepseek-ai/dsh-web'
import { identifyHost, type HostIdentity } from './address.ts'
import { classifyContentType, decoderForCharset, parseCharset } from './content.ts'
import { checkAddresses, checkUrl, isSameOrigin, type Decision, type Target } from './decide.ts'
import { NetguardWebError } from './errors.ts'
import type { ResolvedPolicy } from './policy.ts'
import { denialMessage, REASON_CODES, type DenialReason } from './reasons.ts'

/** One address a resolver returned. */
export interface ResolverAnswer {
  readonly address: string
  readonly family: number
}

/** Name resolution, injectable so the rebinding tests can drive it. */
export type Resolver = (hostname: string) => Promise<readonly ResolverAnswer[]>

/** The system resolver, asked for every address so a mixed A/AAAA answer is fully checked. */
export const systemResolver: Resolver = async (hostname: string) => {
  return await dnsLookup(hostname, { all: true, verbatim: true })
}

/** One decision the provider made, handed to the plugin to record. */
export interface FetchObservation {
  readonly kind: 'fetch' | 'redirect'
  readonly verdict: 'allowed' | 'denied'
  /** False when `mode: audit` let a denied request through. */
  readonly enforced: boolean
  readonly reason?: DenialReason
  readonly rule?: string
  readonly target: Target
  /** The address the socket was pinned to, when one was chosen. */
  readonly resolvedIp?: string
  /** 0 for the requested URL, 1 for the first redirect target, and so on. */
  readonly hop: number
}

/** Notified once per policy decision; must not throw. */
export type FetchObserver = (observation: FetchObservation) => void

/** Everything the provider needs beyond the policy. */
export interface GuardedFetchOptions {
  /** Provider id registered with `ctx.web`; `web.fetchProvider` must name it. */
  readonly id: string
  readonly policy: ResolvedPolicy
  readonly observe: FetchObserver
  /** Name resolution; defaults to {@link systemResolver}. */
  readonly resolve?: Resolver
}

/** HTTP redirect status codes that carry a `Location`. */
function isRedirectStatus(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308
}

/**
 * The address the socket must be pinned to, as a lookup hook Node honours.
 *
 * Global `fetch` ignores a `lookup` in its `RequestInit`; `node:http` and
 * `node:https` honour it, which is the whole reason this provider is built on
 * them. The hook never consults a resolver: it answers with the one address
 * that was already vetted, in whichever of the two callback shapes
 * `net.connect` asked for.
 * @param pinned - the vetted address.
 * @returns the lookup function handed to `http.request`.
 */
export function pinnedLookup(pinned: HostIdentity): LookupFunction {
  const family = pinned.kind === 'ipv4' ? 4 : 6
  return (_hostname, options, callback) => {
    // `net.connect` asks with `all` set when it wants the whole answer; both
    // shapes return the one vetted address and never consult a resolver again.
    if (typeof options === 'object' && options !== null && options.all === true) {
      (callback as unknown as (error: null, addresses: { address: string; family: number }[]) => void)(
        null,
        [{ address: pinned.key, family }],
      )
      return
    }
    (callback as unknown as (error: null, address: string, family: number) => void)(null, pinned.key, family)
  }
}

/**
 * Whether the socket ended up somewhere other than the vetted address.
 *
 * Both sides are canonicalised first: a kernel that reports an accepted IPv4
 * connection as `::ffff:127.0.0.1` is reporting the address that was vetted,
 * not a different one.
 * @param remote - `socket.remoteAddress`, absent while the socket is still connecting.
 * @param pinned - the address the lookup hook returned.
 * @returns true when the connection must be torn down.
 */
export function remoteAddressMismatch(remote: string | undefined, pinned: HostIdentity): boolean {
  if (remote === undefined) return false
  const observed = identifyHost(remote)
  return observed === undefined || observed.key !== pinned.key
}

/** The bytes a capped read produced. */
interface CappedBody {
  readonly bytes: Uint8Array
  readonly truncated: boolean
}

/** The guarded HTTP(S) fetch provider. */
export class GuardedFetchProvider implements WebFetchProvider {
  readonly id: string
  readonly #policy: ResolvedPolicy
  readonly #observe: FetchObserver
  readonly #resolve: Resolver

  /**
   * @param options - the provider id, the resolved policy, the observer, and the resolver.
   */
  constructor(options: GuardedFetchOptions) {
    this.id = options.id
    this.#policy = options.policy
    this.#observe = options.observe
    this.#resolve = options.resolve ?? systemResolver
  }

  /**
   * Whether the provider can run. It always can: the policy is resolved at
   * mount and there is no credential to check.
   * @returns true.
   */
  available(): boolean {
    return true
  }

  /**
   * Retrieve one URL under the policy.
   * @param request - the seam's request; it carries a URL and nothing else.
   * @param signal - the caller's cancellation signal.
   * @returns the fetched resource.
   * @throws NetguardWebError when the policy refuses the request or the transport fails.
   */
  async fetch(request: WebFetchRequest, signal?: AbortSignal): Promise<WebFetchResult> {
    if (signal?.aborted === true) throw new NetguardWebError('web fetch aborted', 'WEB_ABORTED')
    const timeout = AbortSignal.timeout(this.#policy.fetch.timeoutMs)
    const composed = signal === undefined ? timeout : AbortSignal.any([signal, timeout])
    let current = request.url
    for (let hop = 0; ; hop++) {
      const authorised = await this.#authorise(current, hop, composed)
      const response = await this.#send(authorised.target, authorised.pinned, composed, timeout)
      /* v8 ignore next -- a received response always carries a status line; the fallback keeps the comparison total. */
      const redirecting = isRedirectStatus(response.statusCode ?? 0)
      const location = redirecting ? response.headers.location : undefined
      if (redirecting && location === undefined) {
        response.destroy()
        throw new NetguardWebError(
          `redirect response (HTTP ${String(response.statusCode)}) without a Location header`,
          'WEB_PROVIDER_ERROR',
        )
      }
      if (location === undefined) {
        return await this.#readBody(response, authorised.target, composed, timeout)
      }
      response.destroy()
      current = this.#nextHop(location, authorised.target, hop)
    }
  }

  /**
   * Run the whole policy check for one hop and pin the address to connect to.
   * @param raw - the URL for this hop.
   * @param hop - 0 for the requested URL, 1 for the first redirect target.
   * @param signal - the composed cancellation signal.
   * @returns the target and the vetted address the socket is pinned to.
   */
  async #authorise(raw: string, hop: number, signal: AbortSignal): Promise<{ target: Target; pinned: HostIdentity }> {
    const checked = checkUrl(raw, this.#policy)
    if (checked.kind === 'invalid') {
      throw new NetguardWebError(checked.detail, 'WEB_INVALID_URL')
    }
    const { target } = checked
    this.#settle(checked.decision, { kind: hop === 0 ? 'fetch' : 'redirect', target, hop })

    const addresses = await this.#addressesOf(target, signal)
    const addressDecision = checkAddresses(addresses, this.#policy)
    const pinned = addresses[0]?.identity
    this.#settle(addressDecision, {
      kind: hop === 0 ? 'fetch' : 'redirect',
      target,
      hop,
      ...pinned === undefined ? {} : { resolvedIp: pinned.key },
    })
    // Reached only in `audit` mode, where the denial above did not throw: there
    // is still no address to connect to, so the request fails either way.
    if (pinned === undefined) throw new NetguardWebError(`${target.display} resolved to no addresses`, 'WEB_PROVIDER_ERROR')
    return { target, pinned }
  }

  /** Resolve one target, or use its literal address when the URL names one. */
  async #addressesOf(target: Target, signal: AbortSignal): Promise<readonly { identity: HostIdentity; family: 4 | 6 }[]> {
    if (target.identity.kind !== 'name') {
      return [{ identity: target.identity, family: target.identity.kind === 'ipv4' ? 4 : 6 }]
    }
    let answers: readonly ResolverAnswer[]
    try {
      answers = await this.#resolve(target.identity.key)
    } catch (error: unknown) {
      if (signal.aborted) throw new NetguardWebError('web fetch aborted', 'WEB_ABORTED', { cause: error })
      throw new NetguardWebError(`cannot resolve ${target.display}: ${String(error)}`, 'WEB_PROVIDER_ERROR', { cause: error })
    }
    return answers.flatMap((answer) => {
      const identity = identifyHost(answer.address)
      // A resolver that answered with something that is not an address at all
      // is dropped rather than trusted; an empty list is denied downstream.
      return identity === undefined || identity.kind === 'name'
        ? []
        : [{ identity, family: identity.kind === 'ipv4' ? 4 as const : 6 as const }]
    })
  }

  /**
   * Apply one decision: record it, and refuse the request when the mode says to.
   * @param decision - what the policy decided.
   * @param context - the record fields this decision belongs to.
   * @throws NetguardWebError in `enforce` mode when the decision is a denial.
   */
  #settle(decision: Decision, context: { kind: 'fetch' | 'redirect'; target: Target; hop: number; resolvedIp?: string }): void {
    const enforced = this.#policy.mode === 'enforce'
    if (decision.kind === 'allow') {
      this.#observe({
        ...context,
        verdict: 'allowed',
        enforced,
        rule: decision.rule,
      })
      return
    }
    this.#observe({
      ...context,
      verdict: 'denied',
      enforced,
      reason: decision.reason,
      ...decision.rule === undefined ? {} : { rule: decision.rule },
    })
    if (!enforced) return
    throw new NetguardWebError(
      denialMessage(decision.reason, context.target.display, decision.rule),
      REASON_CODES[decision.reason],
    )
  }

  /** Resolve one redirect target, enforcing the hop budget and the same-origin rule. */
  #nextHop(location: string, from: Target, hop: number): string {
    const refuse = (detail: string): never => {
      this.#observe({
        kind: 'redirect',
        verdict: 'denied',
        enforced: true,
        reason: 'blocked-by-redirect',
        rule: `redirect:${detail}`,
        target: from,
        hop,
      })
      throw new NetguardWebError(
        denialMessage('blocked-by-redirect', from.display, `redirect:${detail}`),
        REASON_CODES['blocked-by-redirect'],
      )
    }
    if (hop >= this.#policy.fetch.maxRedirects) return refuse(`exceeded ${String(this.#policy.fetch.maxRedirects)} hops`)
    let next: URL
    try {
      next = new URL(location, from.url)
    } catch {
      // URL resolution against a valid absolute base fails only on a Location
      // that is not a reference at all.
      return refuse('unparseable Location')
    }
    if (!isSameOrigin(from.url, next)) return refuse(`cross-origin to ${next.origin}`)
    return next.toString()
  }

  /** Open one connection to the pinned address and return the response head. */
  async #send(target: Target, pinned: HostIdentity, signal: AbortSignal, timeout: AbortSignal): Promise<IncomingMessage> {
    const secure = target.url.protocol === 'https:'
    const options: RequestOptions = {
      method: 'GET',
      hostname: target.url.hostname.replace(/^\[|\]$/g, ''),
      port: target.port,
      path: `${target.url.pathname}${target.url.search}`,
      headers: {
        'host': target.url.host,
        'user-agent': this.#policy.fetch.userAgent,
        'accept': 'text/html,application/xhtml+xml,text/*;q=0.9,application/json;q=0.8',
        // No compression is negotiated: `node:http` hands back the raw body, and
        // a decompressor between the socket and the size cap is a place for a
        // zip bomb to expand past it.
        'accept-encoding': 'identity',
      },
      lookup: pinnedLookup(pinned),
      // A pooled socket may have been opened for an address an earlier
      // resolution produced, which would make the pinning depend on reuse.
      agent: false,
      signal,
    }
    return await new Promise<IncomingMessage>((resolve, reject) => {
      const send = secure ? httpsRequest : httpRequest
      const req = send(options, resolve)
      req.on('socket', (socket) => {
        const verify = (): void => {
          const remote = socket.remoteAddress
          /* v8 ignore next 8 -- defence in depth: with the lookup hook pinned there is no way to steer the socket elsewhere from the public API, so the mismatch arm cannot be reached from a test. `remoteAddressMismatch` is unit-tested on its own. */
          if (remoteAddressMismatch(remote, pinned)) {
            socket.destroy()
            reject(new NetguardWebError(
              `dsh-netguard refused this request to ${target.display}: the socket connected to ${String(remote)},`
              + ` not the vetted address ${pinned.key}`,
              'WEB_BLOCKED_URL',
            ))
          }
        }
        socket.on('connect', verify)
        socket.on('secureConnect', verify)
      })
      req.on('error', (error: unknown) => { reject(translateTransportError(error, signal, timeout)) })
      req.end()
    })
  }

  /** Read, cap, classify and decode the final response body. */
  async #readBody(response: IncomingMessage, target: Target, signal: AbortSignal, timeout: AbortSignal): Promise<WebFetchResult> {
    const contentType = response.headers['content-type']
    const kind = classifyContentType(contentType)
    if (kind === undefined) {
      response.destroy()
      throw new NetguardWebError(`unsupported content type "${contentType ?? 'unknown'}"`, 'WEB_UNSUPPORTED_CONTENT_TYPE')
    }
    let decoder: TextDecoder
    try {
      decoder = decoderForCharset(parseCharset(contentType))
    } catch (error: unknown) {
      response.destroy()
      throw error
    }
    const declared = Number(response.headers['content-length'])
    if (Number.isFinite(declared) && declared > this.#policy.fetch.maxResponseBytes) {
      response.destroy()
      throw new NetguardWebError(
        `response exceeds the maximum of ${this.#policy.fetch.maxResponseBytes} bytes`,
        'WEB_FETCH_TOO_LARGE',
      )
    }
    const body = await this.#readCapped(response, signal, timeout)
    const decoded = decoder.decode(body.bytes)
    const overChars = decoded.length > this.#policy.fetch.maxBodyChars
    const content = overChars ? decoded.slice(0, this.#policy.fetch.maxBodyChars) : decoded
    return {
      url: target.url.toString(),
      /* v8 ignore next -- a received response always carries a status line; the fallback keeps the result type honest. */
      statusCode: response.statusCode ?? 0,
      body: kind === 'html' ? { kind: 'html', content } : { kind: 'text', content },
      truncated: body.truncated || overChars,
    }
  }

  /** Read the response stream up to the byte cap, cutting rather than failing past it. */
  async #readCapped(response: IncomingMessage, signal: AbortSignal, timeout: AbortSignal): Promise<CappedBody> {
    const chunks: Uint8Array[] = []
    let total = 0
    let truncated = false
    try {
      for await (const chunk of response as AsyncIterable<Uint8Array>) {
        const remaining = this.#policy.fetch.maxResponseBytes - total
        // Only DROPPED bytes count as truncation, so a body that exactly fills
        // the cap is not falsely flagged.
        if (chunk.byteLength > remaining) {
          chunks.push(chunk.subarray(0, remaining))
          total += remaining
          truncated = true
          break
        }
        chunks.push(chunk)
        total += chunk.byteLength
      }
    } catch (error: unknown) {
      throw translateTransportError(error, signal, timeout)
    } finally {
      response.destroy()
    }
    const bytes = new Uint8Array(total)
    let offset = 0
    for (const chunk of chunks) {
      bytes.set(chunk, offset)
      offset += chunk.byteLength
    }
    return { bytes, truncated }
  }
}

/**
 * Classify a transport failure by the signal that fired rather than by the
 * thrown value, which differs between the request and the read phase.
 * @param error - the thrown value.
 * @param signal - the composed signal handed to the request.
 * @param timeout - this provider's own timeout signal.
 * @returns the error to surface to the caller.
 */
export function translateTransportError(error: unknown, signal: AbortSignal, timeout: AbortSignal): Error {
  // A refusal raised by the remote-address check is already the right answer;
  // re-wrapping it as a transport failure would hide the policy decision.
  if (error instanceof NetguardWebError) return error
  if (timeout.aborted) return new NetguardWebError('web fetch timed out', 'WEB_FETCH_TIMEOUT', { cause: error })
  if (signal.aborted) return new NetguardWebError('web fetch aborted', 'WEB_ABORTED', { cause: error })
  return new NetguardWebError(`web fetch failed: ${String(error)}`, 'WEB_PROVIDER_ERROR', { cause: error })
}
