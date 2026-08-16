/**
 * Turning one decision into one spooled OCSF record.
 *
 * This is where the SOC lane's rule is applied: the hostname, the port, the
 * resolved address, the verdict, the matched rule id and the tool name go in
 * verbatim, and the URL and the search query are reduced to a keyed digest and
 * a length. It is also where the per-process sequence number, the first-seen
 * host memory, and the tool-call join are stamped on.
 * @module dsh-netguard/recorder
 */

import type { CallIdentity, TargetCorrelator } from './correlate.ts'
import type { FetchObservation } from './fetch-provider.ts'
import { buildDecisionRecord, type JsonValue, type RecordEnvironment } from './ocsf.ts'
import { digest, digestQuery, digestUrl, HOST_MARKERS, isRecordableHost } from './privacy.ts'
import { newDecisionId } from './sink.ts'
import type { HostMemory, SpoolSink } from './sink.ts'
import type { SearchObservation } from './search-provider.ts'

/** The verdict half of one decision, before identity and sequence are stamped on. */
export interface DecisionFacts {
  readonly kind: 'fetch' | 'redirect' | 'search' | 'guard'
  readonly verdict: 'allowed' | 'denied'
  /** False when `mode: audit` let a denied request through. */
  readonly enforced: boolean
  readonly reason?: FetchObservation['reason'] | undefined
  readonly rule?: string | undefined
  readonly host: string
  readonly port: number
  readonly scheme?: string | undefined
  readonly resolvedIp?: string | undefined
}

/** Everything the recorder needs to turn an observation into a record. */
export interface RecorderOptions {
  readonly env: RecordEnvironment
  readonly sink: SpoolSink
  readonly memory: HostMemory
  /** The URL-or-query to tool-call join minted by the guard. */
  readonly targets: TargetCorrelator
  /** Injectable so tests get deterministic sighting timestamps. */
  readonly clock?: () => Date
}

/** Writes one OCSF record per decision. */
export class Recorder {
  #seq = 0
  readonly #options: RecorderOptions

  /**
   * @param options - the record environment, the sink, the host memory, and the join.
   */
  constructor(options: RecorderOptions) {
    this.#options = options
  }

  /**
   * Record one fetch-provider decision.
   * @param observation - what the provider decided about one hop.
   */
  fetch(observation: FetchObservation): void {
    const { policy } = this.#options.env
    const identity = this.#options.targets.lookup(observation.target.url.toString())
    const url = digestUrl(policy.hmacKey, observation.target.url)
    this.#write(
      {
        kind: observation.kind,
        verdict: observation.verdict,
        enforced: observation.enforced,
        reason: observation.reason,
        rule: observation.rule,
        host: observation.target.identity.key,
        port: observation.target.port,
        scheme: observation.target.url.protocol.replace(':', ''),
        resolvedIp: observation.resolvedIp,
      },
      identity,
      {
        hop: observation.hop,
        url_digest: url.digest,
        url_length: url.length,
        has_query: url.hasQuery,
        // What the decision was actually about, when one address out of several
        // caused it: without this the record names an endpoint that was fine.
        ...observation.detail === undefined ? {} : { detail: observation.detail },
      },
    )
  }

  /**
   * Record one search decision, from the provider or from the guard.
   * @param observation - what the search arm decided.
   * @param identity - the calling tool, when the caller already knows it.
   */
  search(observation: SearchObservation, identity?: CallIdentity): void {
    const { policy } = this.#options.env
    const query = digestQuery(policy.hmacKey, observation.query)
    this.#write(
      {
        kind: 'search',
        verdict: observation.verdict,
        enforced: observation.enforced,
        reason: observation.reason,
        rule: observation.rule,
        host: observation.host,
        port: observation.port,
      },
      identity ?? this.#options.targets.lookup(observation.query),
      {
        query_digest: query.digest,
        query_length: query.length,
        ...observation.droppedSources === undefined ? {} : { dropped_sources: observation.droppedSources },
        ...observation.hostMention === undefined ? {} : { host_mention: observation.hostMention },
        ...observation.sourceUrl === undefined
          ? {}
          : { source_digest: digest(policy.hmacKey, observation.sourceUrl), source_length: observation.sourceUrl.length },
      },
      // A host read out of prose is a word in a question, not a destination
      // this installation contacted. Remembering it would put it in
      // `report --suggest`, which writes allow lists.
      { remember: observation.hostMention !== 'bare' },
    )
  }

  /**
   * Record one decision the tool-tier guard made, before any provider ran.
   * @param decision - the verdict fields.
   * @param identity - the calling tool.
   * @param attributes - the extension-owned attributes this decision adds.
   * @param options - `remember: false` keeps the host out of the host memory.
   */
  guard(
    decision: Omit<DecisionFacts, 'kind'>,
    identity: CallIdentity,
    attributes: Readonly<Record<string, JsonValue>>,
    options: { readonly remember?: boolean } = {},
  ): void {
    this.#write({ ...decision, kind: 'guard' }, identity, attributes, options)
  }

  /**
   * Stamp identity, sequence and first-seen onto one decision and spool it.
   *
   * This is the one place a host reaches a verbatim field, so it is where the
   * lane rule is applied: `dst_endpoint.hostname`, `observables[].value` and
   * `message` carry a plain host spelling or a marker, never an unvalidated
   * string. WHATWG `URL` keeps `'`, `` ` ``, `$`, `;` and `,` in a hostname,
   * and a vendor search result is not this package's text at all.
   */
  #write(
    decision: DecisionFacts,
    identity: CallIdentity | undefined,
    attributes: Readonly<Record<string, JsonValue>>,
    options: { readonly remember?: boolean } = {},
  ): void {
    const clock = this.#options.clock ?? (() => new Date())
    const recordable = isRecordableHost(decision.host)
    const host = recordable ? decision.host : HOST_MARKERS.unrecordableHost
    const firstSeen = options.remember === false
      ? false
      : this.#options.memory.note(host, decision.verdict, clock())
    this.#seq += 1
    this.#options.sink.write(buildDecisionRecord(this.#options.env, {
      ...decision,
      host,
      firstSeen,
      decisionId: newDecisionId(),
      seq: this.#seq,
      ...identity === undefined
        ? {}
        : {
            toolName: identity.toolName,
            callId: identity.callId,
            ...identity.rootCallId === undefined ? {} : { rootCallId: identity.rootCallId },
            ...identity.sessionId === undefined ? {} : { sessionId: identity.sessionId },
            ...identity.turn === undefined ? {} : { turn: identity.turn },
            ...identity.step === undefined ? {} : { step: identity.step },
          },
      attributes: recordable
        ? attributes
        : { ...attributes, host_digest: digest(this.#options.env.policy.hmacKey, decision.host) },
    }))
  }
}
