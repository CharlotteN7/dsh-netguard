/**
 * How many distinct URLs one session has issued against one host.
 *
 * A host allowlist cannot see an exfiltration that never contacts a denied
 * host. CVE-2026-54316 (CWE-515, covert storage channel) is the shape: with
 * `huggingface.co` allowlisted as a bare hostname, the secret is carried by
 * *which* of many URLs on that one allowed host is requested, and the attacker
 * reads it back out of the vendor's own download counters. No response body is
 * needed and no refused host is ever named, so every request in the channel is
 * an ordinary allowed request.
 *
 * What is visible is the shape of the traffic: an agent that suddenly issues
 * dozens of distinct URLs against one allowed host in one session looks nothing
 * like an agent reading documentation. Every full URL is already reduced to an
 * HMAC digest for the record, so counting the distinct digests per
 * `(session, host)` costs nothing extra and stores no URL.
 *
 * This is a signal, not a control. It is a heuristic, and the honest limits are
 * in `docs/limitations.md`: an exfiltrator who stays under the threshold, or
 * spreads the channel over several sessions or several allowed hosts, never
 * trips it.
 *
 * Both caps below exist for the reason the join maps in `correlate.ts` are
 * capped: this state lives for the whole process, and a long session must not
 * be able to grow it without limit.
 * @module dsh-netguard/cardinality
 */

/** `(session, host)` pairs tracked at once; the least recently used is dropped past it. */
const DEFAULT_PAIR_LIMIT = 64

/** Distinct URLs remembered per pair; the count saturates here rather than growing. */
const DEFAULT_URL_LIMIT = 256

/** Caps on the memory this counter may hold. */
export interface UrlCardinalityOptions {
  /** `(session, host)` pairs tracked at once. */
  readonly pairs?: number
  /** Distinct URL digests remembered per pair. */
  readonly urlsPerPair?: number
}

/**
 * The per-process, bounded count of distinct URLs per session and host.
 *
 * Bounded and lossy on purpose, like the two join maps: a dropped pair costs a
 * signal, an unbounded map costs the agent its memory.
 */
export class UrlCardinality {
  readonly #pairs = new Map<string, Set<string>>()
  readonly #pairLimit: number
  readonly #urlLimit: number

  /**
   * @param options - the two caps; the defaults are what the plugin mounts with.
   */
  constructor(options: UrlCardinalityOptions = {}) {
    this.#pairLimit = options.pairs ?? DEFAULT_PAIR_LIMIT
    this.#urlLimit = options.urlsPerPair ?? DEFAULT_URL_LIMIT
  }

  /**
   * Count one request and report the distinct URLs seen for its pair.
   *
   * The digest is what is stored, never the URL, so this holds no more than the
   * spool already does.
   * @param sessionId - the session the request belongs to; requests whose
   *   tool-call join missed share one pair per host, which can only over-count.
   * @param host - the validated hostname or marker the record carries.
   * @param urlDigest - the keyed digest of the full URL.
   * @returns distinct URLs seen for this pair, saturating at the per-pair cap.
   */
  note(sessionId: string | undefined, host: string, urlDigest: string): number {
    // JSON rather than a joined string: no separator can then collide with a
    // character a session id or a hostname is allowed to carry.
    const key = JSON.stringify([sessionId ?? '', host])
    const seen = this.#pairs.get(key) ?? new Set<string>()
    // Re-inserting moves the pair to the end of the iteration order, so the pair
    // being hammered is the last one evicted rather than the first.
    this.#pairs.delete(key)
    this.#pairs.set(key, seen)
    // Past the cap the count stops rising: the signal only has to say "far more
    // than a session should need", and it says that at the threshold.
    if (seen.size < this.#urlLimit) seen.add(urlDigest)
    if (this.#pairs.size > this.#pairLimit) {
      const oldest = this.#pairs.keys().next()
      /* v8 ignore next -- reached only past the limit, so the map is never empty here. */
      if (!oldest.done) this.#pairs.delete(oldest.value)
    }
    return seen.size
  }
}
