/**
 * This plugin's own durable output: the OCSF spool, and the per-installation
 * memory of which hosts have been seen before.
 *
 * Nothing here touches the session log. `Session.append()` offers no way to set
 * the envelope's `ignorable` flag, so an out-of-repo event type is written
 * without it and the user's next resume throws `SessionFormatUnsupportedError`
 * and refuses the whole session. This package is therefore read-side with
 * respect to the log, and every durable record goes to the JSONL file named by
 * `spoolPath`.
 *
 * The host memory is what makes `is_alert` on a first-seen host mean anything
 * across restarts, and it is what `dsh-netguard report --suggest` turns into a
 * ready allow list.
 * @module dsh-netguard/sink
 */

import { randomUUID } from 'node:crypto'
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import type { OcsfRecord } from './ocsf.ts'

declare const decisionIdBrand: unique symbol

/** Producer-minted id correlating one decision across records. */
export type DecisionId = string & { readonly [decisionIdBrand]: true }

/**
 * Mint a decision id.
 * @returns an id unique to one policy decision.
 */
export function newDecisionId(): DecisionId {
  return `netguard-${randomUUID()}` as DecisionId
}

/**
 * Append-only JSONL spool for finished records.
 *
 * There is no rotation in 0.1: this package writes one record per `web_fetch`
 * or `web_search` call rather than one per session event, so the file grows by
 * a few lines per session. A long-lived installation should point `logrotate`
 * at it; README.md says so under the known limits.
 */
export class SpoolSink {
  readonly #path: string
  readonly #onFailure: (error: unknown) => void

  /**
   * @param path - absolute path of the JSONL file to append to.
   * @param onFailure - notified when a write fails; a broken sink never changes a verdict.
   */
  constructor(path: string, onFailure: (error: unknown) => void) {
    this.#path = path
    this.#onFailure = onFailure
    try {
      mkdirSync(dirname(path), { recursive: true })
    } catch (error: unknown) {
      this.#onFailure(error)
    }
  }

  /**
   * Append one record.
   *
   * A write failure is reported and swallowed on purpose: the spool is
   * evidence, not enforcement, and letting a full disk turn every request into
   * a refusal trades an egress control for an availability outage.
   * @param record - the finished OCSF record.
   */
  write(record: OcsfRecord): void {
    try {
      appendFileSync(this.#path, `${JSON.stringify(record)}\n`, { mode: 0o640 })
    } catch (error: unknown) {
      this.#onFailure(error)
    }
  }
}

/** What one installation remembers about one host. */
export interface HostSighting {
  /** ISO-8601 timestamp of the first request to this host. */
  readonly first: string
  /** ISO-8601 timestamp of the most recent request. */
  readonly last: string
  /** Requests the policy allowed. */
  readonly allowed: number
  /** Requests the policy denied, whether or not the mode applied the denial. */
  readonly denied: number
}

/** The persisted host memory document. */
interface HostMemoryDocument {
  readonly v: number
  readonly hosts: Record<string, HostSighting>
}

/** Payload version of the host-memory file. */
export const HOST_MEMORY_VERSION = 1

/**
 * Read one host-memory file.
 *
 * A missing or unreadable file is an empty memory: the file is a convenience
 * for `is_alert` and for the report command, and refusing to start because it
 * is corrupt would turn a cosmetic loss into an outage.
 * @param path - the memory file.
 * @returns the remembered hosts, oldest entry order preserved.
 */
export function readHostMemory(path: string): Map<string, HostSighting> {
  let text: string
  try {
    text = readFileSync(path, 'utf8')
  } catch {
    // ENOENT and unreadable alike: nothing has been remembered yet.
    return new Map()
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    // A truncated write from a killed process; the memory restarts empty.
    return new Map()
  }
  const document = parsed as Partial<HostMemoryDocument>
  if (document.v !== HOST_MEMORY_VERSION || typeof document.hosts !== 'object' || document.hosts === null) {
    return new Map()
  }
  return new Map(Object.entries(document.hosts))
}

/** The per-installation memory of contacted hosts. */
export class HostMemory {
  readonly #path: string
  readonly #onFailure: (error: unknown) => void
  readonly #hosts: Map<string, HostSighting>

  /**
   * @param path - the memory file, read once at construction.
   * @param onFailure - notified when the file cannot be written.
   */
  constructor(path: string, onFailure: (error: unknown) => void) {
    this.#path = path
    this.#onFailure = onFailure
    this.#hosts = readHostMemory(path)
  }

  /**
   * Record one request and report whether the host was new.
   * @param host - the canonical hostname.
   * @param verdict - what the policy decided.
   * @param time - the sighting time.
   * @returns true when this installation had never contacted the host before.
   */
  note(host: string, verdict: 'allowed' | 'denied', time: Date): boolean {
    const stamp = time.toISOString()
    const existing = this.#hosts.get(host)
    this.#hosts.set(host, {
      first: existing?.first ?? stamp,
      last: stamp,
      allowed: (existing?.allowed ?? 0) + (verdict === 'allowed' ? 1 : 0),
      denied: (existing?.denied ?? 0) + (verdict === 'denied' ? 1 : 0),
    })
    this.#persist()
    return existing === undefined
  }

  /** Write the memory back, reporting a failure rather than failing the request. */
  #persist(): void {
    const document: HostMemoryDocument = {
      v: HOST_MEMORY_VERSION,
      hosts: Object.fromEntries(this.#hosts.entries()),
    }
    try {
      mkdirSync(dirname(this.#path), { recursive: true })
      writeFileSync(this.#path, `${JSON.stringify(document, undefined, 2)}\n`, { mode: 0o640 })
    } catch (error: unknown) {
      this.#onFailure(error)
    }
  }
}
