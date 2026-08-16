/**
 * The two joins this package has to mint for itself.
 *
 * A `WebFetchProvider` is handed `{ url }` and nothing else — no agent, no
 * session, no call id (`packages/web/web/src/types.ts:113`). And the
 * `SessionEvent` envelope carries only `type`, `seq`, `time` and `data`, so a
 * tool execution does not know its own turn or step either. Without both joins
 * a record can say *a connection to this host happened* but not *which tool
 * call opened it*, which is the one thing this package exists to answer.
 *
 * So the tool tier mints the identity: `ctx.tools.guard()` sees the
 * `web_fetch` execution, with its `callId`, its `rootCallId` and its agent's
 * session, and notes it against the URL the model asked for; the provider looks
 * that URL up when it is called moments later. `turn` and `step` come from the
 * `tool/call` session event, the only place they appear beside a `callId`.
 *
 * Both maps are bounded and lossy on purpose. A missed join costs a record its
 * `correlation_uid`; an unbounded map costs the agent its memory.
 * @module dsh-netguard/correlate
 */

/** Turn and step of one in-flight tool call. */
export interface CallPosition {
  readonly turn: number
  readonly step: number
}

/**
 * Remembers where each in-flight tool call sits in the session.
 *
 * `Agent` exposes no turn or step and the tool pipeline hands listeners only a
 * `ToolExecution`, so following the session firehose is the only way to label a
 * record with its position.
 */
export class CallCorrelator {
  readonly #positions = new Map<string, CallPosition>()
  readonly #limit: number

  /**
   * @param limit - maximum remembered calls; the oldest entry is dropped past it.
   */
  constructor(limit = 512) {
    this.#limit = limit
  }

  /**
   * Record one call's position.
   * @param callId - the call's id from the `tool/call` event.
   * @param position - the turn and step that event reported.
   */
  note(callId: string, position: CallPosition): void {
    this.#positions.set(callId, position)
    if (this.#positions.size > this.#limit) {
      const oldest = this.#positions.keys().next()
      /* v8 ignore next -- reached only past the limit, so the map is never empty here. */
      if (!oldest.done) this.#positions.delete(oldest.value)
    }
  }

  /**
   * Forget one call.
   * @param callId - the call whose result has been committed.
   */
  forget(callId: string): void {
    this.#positions.delete(callId)
  }

  /**
   * Look one call's position up.
   * @param callId - the call to locate.
   * @returns its turn and step, or `undefined` when the call was never seen.
   */
  lookup(callId: string): CallPosition | undefined {
    return this.#positions.get(callId)
  }
}

/** Everything a record needs about the tool call that caused a request. */
export interface CallIdentity {
  readonly toolName: string
  readonly callId: string
  readonly rootCallId?: string
  readonly sessionId?: string
  readonly turn?: number
  readonly step?: number
}

/**
 * Remembers which tool call asked for which URL.
 *
 * The entry is kept rather than consumed on lookup: one `web_fetch` call may
 * produce several requests as the provider follows redirects, and every hop
 * belongs to the same tool call. Entries expire by age, oldest first.
 */
export class TargetCorrelator {
  readonly #byUrl = new Map<string, CallIdentity>()
  readonly #limit: number

  /**
   * @param limit - maximum remembered URLs; the oldest entry is dropped past it.
   */
  constructor(limit = 64) {
    this.#limit = limit
  }

  /**
   * Note the call that is about to request one URL.
   * @param url - the URL exactly as the model wrote it.
   * @param identity - the calling tool's identity.
   */
  note(url: string, identity: CallIdentity): void {
    // Re-inserting moves the entry to the end of the iteration order, so a URL
    // fetched repeatedly is not the first one evicted.
    this.#byUrl.delete(url)
    this.#byUrl.set(url, identity)
    if (this.#byUrl.size > this.#limit) {
      const oldest = this.#byUrl.keys().next()
      /* v8 ignore next -- reached only past the limit, so the map is never empty here. */
      if (!oldest.done) this.#byUrl.delete(oldest.value)
    }
  }

  /**
   * Look up the call that asked for one URL.
   * @param url - the URL the provider was handed.
   * @returns the calling tool's identity, or `undefined` when the request did
   *   not come through a guarded tool call.
   */
  lookup(url: string): CallIdentity | undefined {
    return this.#byUrl.get(url)
  }
}
