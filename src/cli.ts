#!/usr/bin/env node
/**
 * `dsh-netguard report` — read the OCSF spool and say what the policy decided,
 * and `--suggest` — print the allow list audit mode observed.
 *
 * That second half is the point of audit mode. Nobody can enumerate the hosts a
 * dependency graph reaches in advance, so an enforce-first allowlist gets
 * switched off in week one; running in audit for a while and reading the
 * observed hosts back out is how the real list gets written.
 *
 * The command imports nothing from the harness, so it runs wherever the package
 * is installed, with no profile and no `dsh` on the path. The spool is a durable
 * boundary — written by an older version of this package, appended to under
 * crash — so every line is parsed defensively and a line that is not a record
 * is counted rather than trusted.
 * @module dsh-netguard/cli
 */

import { readFileSync, realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { defaultSpoolPath } from './home.ts'
import { HOST_MARKERS } from './privacy.ts'

/** How many decisions the report lists individually. */
const RECENT_LIMIT = 10

/** One spooled record, after the fields this command reads are checked. */
export interface ReportRecord {
  /** Epoch milliseconds from the record's `time`. */
  readonly time: number
  readonly host: string
  readonly port: number
  readonly verdict: string
  readonly enforced: boolean
  readonly mode: string
  readonly kind: string
  readonly reason?: string
  readonly rule?: string
  readonly tool?: string
  readonly sessionId?: string
  readonly resolvedIp?: string
  /** How a search query named the host: `url`, `operator`, or `bare` prose. */
  readonly hostMention?: string
}

/** The extension-owned attributes of one record, with the two fields every one carries. */
interface Attributes {
  readonly all: Record<string, unknown>
  readonly verdict: string
  readonly kind: string
}

/** The extension-owned attributes of one record, wherever they were placed. */
function attributesOf(record: Record<string, unknown>): Attributes | undefined {
  const unmapped = record['unmapped']
  const candidates: unknown[] = []
  if (typeof unmapped === 'object' && unmapped !== null) candidates.push(...Object.values(unmapped))
  // `extension.placement: attribute` puts them at the top level under the
  // extension's own name, which this command does not know; every top-level
  // object carrying our version marker is accepted.
  candidates.push(...Object.values(record))
  for (const candidate of candidates) {
    if (typeof candidate !== 'object' || candidate === null || Array.isArray(candidate)) continue
    const all = candidate as Record<string, unknown>
    const { verdict, kind } = all
    if (typeof verdict === 'string' && typeof kind === 'string') return { all, verdict, kind }
  }
  return undefined
}

/** Read one string field, or `undefined` when it is absent or not a string. */
function stringField(source: Record<string, unknown>, key: string): string | undefined {
  const value = source[key]
  return typeof value === 'string' ? value : undefined
}

/**
 * Parse one JSONL line into the fields this command reports on.
 * @param line - one line of the spool.
 * @returns the record, or `undefined` when the line is not one.
 */
export function parseRecord(line: string): ReportRecord | undefined {
  let parsed: unknown
  try {
    parsed = JSON.parse(line)
  } catch {
    // A torn final line from an interrupted append is the expected cause.
    return undefined
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return undefined
  const record = parsed as Record<string, unknown>
  const found = attributesOf(record)
  if (found === undefined) return undefined
  const attributes = found.all
  const destination = record['dst_endpoint']
  const endpoint = typeof destination === 'object' && destination !== null
    ? destination as Record<string, unknown>
    : {}
  const host = stringField(endpoint, 'hostname') ?? stringField(attributes, 'host')
  if (host === undefined) return undefined
  return {
    time: typeof record['time'] === 'number' ? record['time'] : 0,
    host,
    port: typeof endpoint['port'] === 'number' ? endpoint['port'] : 0,
    verdict: found.verdict,
    enforced: attributes['enforced'] === true,
    mode: stringField(attributes, 'mode') ?? 'unknown',
    kind: found.kind,
    ...stringField(attributes, 'reason') === undefined ? {} : { reason: stringField(attributes, 'reason') as string },
    ...stringField(attributes, 'rule') === undefined ? {} : { rule: stringField(attributes, 'rule') as string },
    ...stringField(attributes, 'tool') === undefined ? {} : { tool: stringField(attributes, 'tool') as string },
    ...stringField(attributes, 'session_id') === undefined ? {} : { sessionId: stringField(attributes, 'session_id') as string },
    ...stringField(endpoint, 'ip') === undefined ? {} : { resolvedIp: stringField(endpoint, 'ip') as string },
    ...stringField(attributes, 'host_mention') === undefined
      ? {}
      : { hostMention: stringField(attributes, 'host_mention') as string },
  }
}

/** What reading the spool produced. */
export type SpoolRead =
  | { readonly kind: 'absent' }
  | { readonly kind: 'unreadable'; readonly problem: string }
  | { readonly kind: 'read'; readonly records: readonly ReportRecord[]; readonly unreadable: number }

/**
 * Read and parse the spool.
 * @param path - the spool file.
 * @returns the parsed records, the file's absence, or the problem to report.
 */
export function readSpool(path: string): SpoolRead {
  let text: string
  try {
    text = readFileSync(path, 'utf8')
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { kind: 'absent' }
    return { kind: 'unreadable', problem: `cannot read ${path}: ${String(error)}` }
  }
  const lines = text.split('\n').filter(line => line.trim().length > 0)
  const records = lines.map(parseRecord).filter((record): record is ReportRecord => record !== undefined)
  return { kind: 'read', records, unreadable: lines.length - records.length }
}

/** The options `dsh-netguard report` accepts. */
export interface ReportOptions {
  readonly spool: string
  /** Lower bound on record time, in epoch milliseconds. */
  readonly since?: number
  readonly session?: string
  /** Print a ready allow list instead of the decision summary. */
  readonly suggest: boolean
}

/** One parsed command line. */
export type Invocation =
  | { readonly kind: 'report'; readonly options: ReportOptions }
  | { readonly kind: 'usage' }
  | { readonly kind: 'error'; readonly message: string }

/** Parse a `24h`, `30m`, `7d` or ISO-8601 lower bound into epoch milliseconds. */
export function parseSince(text: string, now: number): number | undefined {
  const relative = /^(\d+)([smhd])$/.exec(text)
  if (relative !== null) {
    const units: Record<string, number> = { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 }
    return now - Number(relative[1]) * (units[relative[2] as string] as number)
  }
  const absolute = Date.parse(text)
  return Number.isNaN(absolute) ? undefined : absolute
}

/**
 * Parse the command line.
 * @param argv - arguments after the command name.
 * @param env - environment consulted for `DSH_HOME`.
 * @param now - clock used for a relative `--since`.
 * @returns the parsed invocation.
 */
export function parseArgv(argv: readonly string[], env: NodeJS.ProcessEnv, now: number): Invocation {
  const [command, ...rest] = argv
  if (command === undefined || command === '--help' || command === '-h' || command === 'help') return { kind: 'usage' }
  if (command !== 'report') return { kind: 'error', message: `unknown command "${command}"` }
  let spool = defaultSpoolPath(env)
  let since: number | undefined
  let session: string | undefined
  let suggest = false
  for (let index = 0; index < rest.length; index++) {
    const flag = rest[index]
    const value = rest[index + 1]
    if (flag === '--suggest') { suggest = true; continue }
    if (value === undefined) return { kind: 'error', message: `${String(flag)} needs a value` }
    if (flag === '--spool') { spool = value; index++; continue }
    if (flag === '--session') { session = value; index++; continue }
    if (flag === '--since') {
      const parsed = parseSince(value, now)
      if (parsed === undefined) return { kind: 'error', message: `--since "${value}" is not a duration or an ISO timestamp` }
      since = parsed
      index++
      continue
    }
    return { kind: 'error', message: `unknown option "${String(flag)}"` }
  }
  return {
    kind: 'report',
    options: {
      spool,
      suggest,
      ...since === undefined ? {} : { since },
      ...session === undefined ? {} : { session },
    },
  }
}

/** Count occurrences of each key, most frequent first. */
function tally(values: readonly string[]): readonly (readonly [string, number])[] {
  const counts = new Map<string, number>()
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1)
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
}

/** The records a report covers, after `--since` and `--session`. */
export function selectRecords(records: readonly ReportRecord[], options: ReportOptions): readonly ReportRecord[] {
  return records.filter(record => (options.since === undefined || record.time >= options.since)
    && (options.session === undefined || record.sessionId === options.session))
}

/**
 * Hosts this command will write into a YAML allow list.
 *
 * The spool is a durable boundary: it is written by other versions of this
 * package, and a record's hostname can be a string a vendor or a model chose.
 * The output of `--suggest` is documented as ready to paste into `cordis.yml`,
 * so anything that is not a plain host spelling — a quote, a newline, an
 * `allow:` line of its own — is left out rather than quoted and hoped for.
 */
const SUGGESTABLE_HOST = /^[a-z0-9._-]+$/

/**
 * Render the allow list the observed decisions imply.
 * @param records - the selected records.
 * @returns the lines to print: a ready `allow:` block.
 */
export function formatSuggestion(records: readonly ReportRecord[]): readonly string[] {
  // A host a query merely named in prose is a word in a question, not a
  // destination anything connected to. A marker stands in for a decision that
  // had no hostname at all, and belongs in no allow list.
  const markers = new Set<string>(Object.values(HOST_MARKERS))
  const usable = records.filter(record => record.hostMention !== 'bare' && !markers.has(record.host))
  const observed = [...new Set(usable.map(record => record.host))].sort()
  const hosts = observed.filter(host => SUGGESTABLE_HOST.test(host))
  const skipped = observed.length - hosts.length
  const note = skipped === 0
    ? []
    : [`# ${String(skipped)} recorded value(s) are not host names and were left out; read them with the report itself.`]
  if (hosts.length === 0) return ['# dsh-netguard observed no hosts in the selected records.', ...note]
  return [
    '# Allow list derived from observed hosts. Read every line before using it:',
    '# audit mode records what happened, not what should be permitted, and one',
    '# entry here may be the request you mounted this plugin to stop.',
    ...note,
    'allow:',
    ...hosts.map((host) => {
      const seen = usable.filter(record => record.host === host)
      const denied = seen.filter(record => record.verdict === 'denied').length
      return `  - '${host}'   # ${String(seen.length)} request(s), ${String(denied)} the policy would refuse`
    }),
  ]
}

/**
 * Render the decision summary.
 * @param records - the selected records.
 * @param unreadable - lines that did not parse as records.
 * @param options - the invocation's options, for the header.
 * @returns the lines to print.
 */
export function formatReport(
  records: readonly ReportRecord[],
  unreadable: number,
  options: ReportOptions,
): readonly string[] {
  if (options.suggest) return formatSuggestion(records)
  const lines: string[] = [`dsh-netguard: ${String(records.length)} decision(s) in ${options.spool}`]
  if (unreadable > 0) lines.push(`${String(unreadable)} line(s) did not parse as records and were skipped.`)
  if (records.length === 0) return lines

  const denied = records.filter(record => record.verdict === 'denied')
  const wouldHave = denied.filter(record => !record.enforced)
  lines.push(
    '',
    `allowed: ${String(records.length - denied.length)}   denied: ${String(denied.length)}`
    + `   of those, recorded but permitted by audit mode: ${String(wouldHave.length)}`,
  )
  for (const [label, values] of [
    ['by reason', denied.map(record => record.reason ?? 'unknown')],
    ['by rule', records.flatMap(record => record.rule === undefined ? [] : [record.rule])],
    ['by tool', records.flatMap(record => record.tool === undefined ? [] : [record.tool])],
    ['by host', records.map(record => record.host)],
  ] as const) {
    const counts = tally(values)
    if (counts.length === 0) continue
    lines.push('', label)
    for (const [key, count] of counts) lines.push(`  ${String(count).padStart(6)}  ${key}`)
  }

  lines.push('', `most recent ${String(Math.min(RECENT_LIMIT, records.length))}`)
  for (const record of [...records].sort((a, b) => b.time - a.time).slice(0, RECENT_LIMIT)) {
    const applied = record.verdict === 'denied' && !record.enforced ? ' (audit: permitted)' : ''
    lines.push(
      `  ${new Date(record.time).toISOString()}  ${record.verdict.padEnd(7)} ${record.host}:${String(record.port)}`
      + `${record.resolvedIp === undefined ? '' : ` [${record.resolvedIp}]`}`
      + `${record.reason === undefined ? '' : ` ${record.reason}`}${applied}`,
    )
  }
  return lines
}

/** The usage text. */
const USAGE = [
  'Usage: dsh-netguard report [options]',
  '',
  '  --spool <path>     the OCSF spool to read (default: $DSH_HOME/netguard/decisions.ocsf.jsonl)',
  '  --since <when>     only records at or after this point: 30m, 24h, 7d, or an ISO timestamp',
  '  --session <id>     only records from one session',
  '  --suggest          print a ready allow list built from the observed hosts',
]

/**
 * Run the command.
 * @param argv - arguments after the command name.
 * @param write - stdout line writer.
 * @param fail - stderr line writer.
 * @param env - environment consulted for `DSH_HOME`.
 * @param now - clock used for a relative `--since`.
 * @returns the process exit code.
 */
export function main(
  argv: readonly string[],
  write: (line: string) => void,
  fail: (line: string) => void,
  env: NodeJS.ProcessEnv = process.env,
  now: number = Date.now(),
): number {
  const invocation = parseArgv(argv, env, now)
  if (invocation.kind === 'usage') {
    for (const line of USAGE) write(line)
    return 0
  }
  if (invocation.kind === 'error') {
    fail(`dsh-netguard: ${invocation.message}`)
    for (const line of USAGE) fail(line)
    return 2
  }
  const file = readSpool(invocation.options.spool)
  switch (file.kind) {
    case 'absent':
      write(`dsh-netguard: no spool at ${invocation.options.spool}`)
      write('Nothing has been recorded yet, or the deployment set `spoolPath` elsewhere — pass --spool <path>.')
      return 0
    case 'unreadable':
      fail(`dsh-netguard: ${file.problem}`)
      return 1
    case 'read':
      for (const line of formatReport(selectRecords(file.records, invocation.options), file.unreadable, invocation.options)) {
        write(line)
      }
      return 0
    /* v8 ignore next 4 -- unreachable while `SpoolRead` stays closed; the arm exists so adding a variant fails the build. */
    default: {
      const unhandled: never = file
      throw new TypeError(`dsh-netguard: unhandled spool read ${JSON.stringify(unhandled)}`)
    }
  }
}

/* v8 ignore start -- the process entry, exercised by tests/e2e/report.e2e.ts against the built CLI rather than by the instrumented unit run. */
if (process.argv[1] !== undefined && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(
    process.argv.slice(2),
    line => process.stdout.write(`${line}\n`),
    line => process.stderr.write(`${line}\n`),
  )
}
/* v8 ignore stop */
