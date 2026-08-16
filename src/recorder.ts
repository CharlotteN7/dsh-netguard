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
import { digestQuery, digestUrl } from './privacy.ts'
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
      { hop: observation.hop, url_digest: url.digest, url_length: url.length, has_query: url.hasQuery },
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
      },
    )
  }

  /**
   * Record one decision the tool-tier guard made, before any provider ran.
   * @param decision - the verdict fields.
   * @param identity - the calling tool.
   * @param attributes - the extension-owned attributes this decision adds.
   */
  guard(
    decision: Omit<DecisionFacts, 'kind'>,
    identity: CallIdentity,
    attributes: Readonly<Record<string, JsonValue>>,
  ): void {
    this.#write({ ...decision, kind: 'guard' }, identity, attributes)
  }

  /** Stamp identity, sequence and first-seen onto one decision and spool it. */
  #write(
    decision: DecisionFacts,
    identity: CallIdentity | undefined,
    attributes: Readonly<Record<string, JsonValue>>,
  ): void {
    const clock = this.#options.clock ?? (() => new Date())
    const firstSeen = this.#options.memory.note(decision.host, decision.verdict, clock())
    this.#seq += 1
    this.#options.sink.write(buildDecisionRecord(this.#options.env, {
      ...decision,
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
      attributes,
    }))
  }
}
