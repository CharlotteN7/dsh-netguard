/**
 * Deployment configuration, the repo-local policy tier, and the tighten-only
 * merge between them.
 *
 * Trust ranking, highest first:
 *
 * 1. invariants compiled into this package — the refused-address table, the
 *    pattern grammar, the reason vocabulary; not configurable;
 * 2. `cordis.yml` / bundle patch config — deployment-controlled; sets every field;
 * 3. `policyFile` — a repo-local YAML file; **attacker-controlled**, may only tighten.
 *
 * Rank 3 is a file inside the workspace, so a hostile repository ships one and
 * a prompt-injected agent can write one. It may add deny patterns and switch
 * audit mode up to enforce. It may not add an allow pattern, drop back to
 * audit, open an address range, or name the spool — there is no legitimate
 * reason for a workspace to widen an egress allowlist, and the harness itself
 * takes the same line by forbidding a repo-local `.env` from setting
 * `HTTP_PROXY`.
 * @module dsh-netguard/policy
 */

import { randomBytes, randomUUID } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, join } from 'node:path'
import { JSON_SCHEMA, load } from 'js-yaml'
import z from '@deepseek-ai/schemastery'
import { overlapsUnopenable, parseCidr, type Cidr } from './address.ts'
import { PolicyError } from './errors.ts'
import { resolveDshHome } from './home.ts'
import { HostPolicy } from './hosts.ts'

/** Whether a decision is only recorded, or also refused. */
export type Mode = 'audit' | 'enforce'

/** Where the digest key comes from. */
export type HmacKeySource = 'ephemeral' | 'env' | 'literal'

/** Where the extension-owned attributes are attached to a record. */
export type ExtensionPlacement = 'attribute' | 'unmapped'

/** A vendor search provider this package wraps, named for dynamic resolution. */
export interface SearchDelegateConfig {
  /** Package or file specifier the delegate class is imported from. */
  module?: string
  /** Named export of the delegate class. */
  export?: string
  /** Constructor argument handed to the delegate class, verbatim. */
  options?: Record<string, unknown>
}

/** Plugin configuration, as written in `cordis.yml`. */
export interface Config {
  /**
   * `audit` records every decision and refuses nothing. It is the default, and
   * it is not a control — see README.md.
   */
  mode?: Mode
  /** Allow patterns. Empty denies everything, which is the shipped default. */
  allow?: string[]
  /** Deny patterns; a deny match wins over every allow match. */
  deny?: string[]
  /**
   * Private ranges this deployment opens, as CIDR blocks. Cloud metadata and
   * the link-local range are refused here at load: an agent that can reach
   * `169.254.169.254` holds the host's cloud role.
   */
  allowPrivateAddresses?: string[]
  /** Optional repo-local policy file; the lowest-trust source. */
  policyFile?: string
  /** Absolute path of this plugin's own OCSF spool. Never the session log. */
  spoolPath: string
  /** Absolute path of the already-seen host memory; defaults to `<spoolPath>.hosts`. */
  hostMemoryPath?: string
  /** Provider id this package registers with `ctx.web`; `web.fetchProvider` must name it. */
  fetchProviderId?: string
  /** Provider id the guarded search provider registers under. */
  searchProviderId?: string
  /** Guarded fetch provider settings. */
  fetch?: {
    /** Whether the fetch provider is registered at all. */
    enabled?: boolean
    maxUrlLength?: number
    maxResponseBytes?: number
    maxBodyChars?: number
    timeoutMs?: number
    maxRedirects?: number
    userAgent?: string
  }
  /** Guarded search provider settings. */
  search?: {
    /** Whether the search arms (the outbound-query guard and the provider) run. */
    enabled?: boolean
    /** Longest query whose hosts are read; a longer one is refused rather than scanned. */
    maxQueryLength?: number
    /** The vendor provider this package wraps; absent leaves the provider unusable. */
    delegate?: SearchDelegateConfig
  }
  /** Redaction key for the digests that stand in for URLs and queries. */
  hmacKey?: {
    source?: HmacKeySource
    /** Environment variable holding the key; required when `source` is `env`. */
    variable?: string
    /** Literal key; required when `source` is `literal`. */
    value?: string
  }
  /** Fleet identity stamped into `metadata` and `device` on every record. */
  fleet?: {
    tenantUid?: string
    labels?: string[]
    tags?: Record<string, string>
    installUid?: string
    installUidPath?: string
  }
  /** Identity written into `metadata.extensions[]`; `name` also keys the attributes object. */
  extension?: {
    name?: string
    /** OCSF extension uid as assigned by the registry; omitted until a deployment has one. */
    uid?: number
    placement?: ExtensionPlacement
  }
  /** Vendor name written into `metadata.product`. */
  vendorName?: string
}

/** Longest URL this package decides; a longer one is denied. */
const DEFAULT_MAX_URL_LENGTH = 2048

/** Longest search query whose hosts are read; a longer one is denied unscanned. */
const DEFAULT_MAX_QUERY_LENGTH = 2048

/** Largest response body read, in bytes. */
const DEFAULT_MAX_RESPONSE_BYTES = 5_000_000

/** Largest decoded body handed back, in characters. */
const DEFAULT_MAX_BODY_CHARS = 100_000

/** Per-request budget covering connect, response and body read. */
const DEFAULT_TIMEOUT_MS = 30_000

/** Redirect hops followed, each re-checked in full. */
const DEFAULT_MAX_REDIRECTS = 5

/** `User-Agent` sent on every request: an explicit product agent, never a browser disguise. */
export const DEFAULT_USER_AGENT = 'dsh-netguard/0.1.0 (+https://github.com/CharlotteN7/dsh-netguard)'

/** Provider id both guarded providers register under unless a deployment renames them. */
export const DEFAULT_PROVIDER_ID = 'dsh-netguard'

/** Vendor reported in `metadata.product.vendor_name`. */
const DEFAULT_VENDOR_NAME = 'dsh-security-plugins'

/** Minimum accepted length of a configured HMAC key, in bytes. */
const MIN_HMAC_KEY_BYTES = 32

/** Schemastery validator for {@link Config}. */
export const Config: z<Config> = z.object({
  mode: z.union(['audit', 'enforce'] as const).default('audit'),
  allow: z.array(z.string()).default([]),
  deny: z.array(z.string()).default([]),
  allowPrivateAddresses: z.array(z.string()).default([]),
  policyFile: z.string(),
  spoolPath: z.string().required(),
  hostMemoryPath: z.string(),
  fetchProviderId: z.string().default(DEFAULT_PROVIDER_ID),
  searchProviderId: z.string().default(DEFAULT_PROVIDER_ID),
  fetch: z.object({
    enabled: z.boolean().default(true),
    maxUrlLength: z.number().default(DEFAULT_MAX_URL_LENGTH),
    maxResponseBytes: z.number().default(DEFAULT_MAX_RESPONSE_BYTES),
    maxBodyChars: z.number().default(DEFAULT_MAX_BODY_CHARS),
    timeoutMs: z.number().default(DEFAULT_TIMEOUT_MS),
    maxRedirects: z.number().default(DEFAULT_MAX_REDIRECTS),
    userAgent: z.string().default(DEFAULT_USER_AGENT),
  }),
  search: z.object({
    enabled: z.boolean().default(true),
    maxQueryLength: z.number().default(DEFAULT_MAX_QUERY_LENGTH),
    delegate: z.object({
      module: z.string(),
      export: z.string(),
      options: z.dict(z.any()).default({}),
    }),
  }),
  hmacKey: z.object({
    source: z.union(['ephemeral', 'env', 'literal'] as const).default('ephemeral'),
    variable: z.string(),
    value: z.string(),
  }),
  fleet: z.object({
    tenantUid: z.string(),
    labels: z.array(z.string()).default([]),
    tags: z.dict(z.string()).default({}),
    installUid: z.string(),
    installUidPath: z.string(),
  }),
  extension: z.object({
    name: z.string().default('dsh'),
    uid: z.number(),
    placement: z.union(['attribute', 'unmapped'] as const).default('unmapped'),
  }),
  vendorName: z.string().default(DEFAULT_VENDOR_NAME),
})

/** Payload version this package writes and accepts for repo-local policy files. */
export const POLICY_VERSION = 1

/** Keys a repo-local policy file may carry; anything else fails the load. */
const POLICY_KEYS = ['v', 'addDeny', 'enforce'] as const

/** A repo-local policy file after parsing and validation. */
export interface RepoPolicy {
  /** Deny patterns added to the deployment's own list. */
  readonly addDeny: readonly string[]
  /** True to raise `audit` to `enforce`; it can never lower `enforce` to `audit`. */
  readonly enforce: boolean
}

/**
 * Parse and validate one repo-local policy document.
 *
 * Loaded under `js-yaml`'s `JSON_SCHEMA`, so a `!!js/function` tag is a parse
 * error rather than code execution. This path deliberately never touches the
 * Cordis loader, whose `!!js` support is the whole reason it must not read
 * workspace-authored files.
 * @param text - the file's contents.
 * @returns the validated policy.
 * @throws PolicyError on an unknown key, a bad value, or any attempt to loosen.
 */
export function parseRepoPolicy(text: string): RepoPolicy {
  let parsed: unknown
  try {
    parsed = load(text, { schema: JSON_SCHEMA })
  } catch (error: unknown) {
    throw new PolicyError(`file is not safe-schema YAML: ${String(error)}`)
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new PolicyError('file must be a mapping')
  }
  const document = parsed as Record<string, unknown>
  const unknown = Object.keys(document).filter(key => !(POLICY_KEYS as readonly string[]).includes(key))
  if (unknown.length > 0) {
    throw new PolicyError(
      `unknown keys: ${unknown.join(', ')}. A repo-local policy may only tighten: ${POLICY_KEYS.join(', ')}`,
    )
  }
  if (document['v'] !== POLICY_VERSION) throw new PolicyError(`v must be ${POLICY_VERSION}`)

  const addDeny = document['addDeny'] ?? []
  if (!Array.isArray(addDeny) || addDeny.some(entry => typeof entry !== 'string')) {
    throw new PolicyError('addDeny must be a list of strings')
  }
  // Compiled here so a malformed pattern invalidates the file at load rather
  // than at the first request it would have decided.
  for (const pattern of addDeny as string[]) HostPolicy.compile([], [pattern])

  const enforce = document['enforce'] ?? false
  if (typeof enforce !== 'boolean') throw new PolicyError('enforce must be true or false')
  if (enforce === false && document['enforce'] !== undefined) {
    throw new PolicyError('enforce: false would relax the deployment\'s mode; a repo-local policy may only tighten')
  }
  return { addDeny: addDeny as string[], enforce }
}

/** Outcome of reading the file named by `policyFile`. */
export type RepoPolicyLoad =
  /** No file at that path: the workspace ships no policy. */
  | { readonly kind: 'absent' }
  | { readonly kind: 'loaded'; readonly policy: RepoPolicy }
  /** Present but unreadable or invalid; `problem` is what to report. */
  | { readonly kind: 'invalid'; readonly problem: string }

/**
 * Read a repo-local policy file from disk.
 *
 * Absence is not a misconfiguration: `policyFile` names a path inside the
 * *workspace*, and the recommended value is workspace-relative, so most
 * repositories have none. Failing the mount would refuse to start `dsh`
 * everywhere the file is missing, and would hand a hostile repository a way to
 * remove the plugin by deleting or breaking it. A malformed file is loud and
 * ignored, never obeyed in part.
 * @param path - the file to read.
 * @returns the validated policy, its absence, or the problem to report.
 */
export function loadRepoPolicy(path: string): RepoPolicyLoad {
  let text: string
  try {
    text = readFileSync(path, 'utf8')
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { kind: 'absent' }
    return { kind: 'invalid', problem: `cannot read ${path}: ${String(error)}` }
  }
  try {
    return { kind: 'loaded', policy: parseRepoPolicy(text) }
  } catch (error: unknown) {
    return { kind: 'invalid', problem: String(error) }
  }
}

/** The complete fetch-provider limits, after defaults. */
export interface FetchLimits {
  readonly enabled: boolean
  readonly maxUrlLength: number
  readonly maxResponseBytes: number
  readonly maxBodyChars: number
  readonly timeoutMs: number
  readonly maxRedirects: number
  readonly userAgent: string
}

/** The fleet identity every record carries. */
export interface ResolvedFleet {
  readonly tenantUid: string | undefined
  readonly labels: readonly string[] | undefined
  readonly tags: readonly { readonly name: string; readonly value: string }[] | undefined
  readonly installUid: string
}

/** Everything the seams read after both tiers have been merged. */
export interface ResolvedPolicy {
  readonly mode: Mode
  readonly hosts: HostPolicy
  /** Private ranges the deployment opened; never a cloud-metadata or link-local address. */
  readonly openedAddresses: readonly Cidr[]
  readonly spoolPath: string
  readonly hostMemoryPath: string
  readonly fetchProviderId: string
  readonly searchProviderId: string
  readonly fetch: FetchLimits
  readonly searchEnabled: boolean
  /** Longest query the outbound-query arm reads; past it the query is denied unscanned. */
  readonly searchMaxQueryLength: number
  readonly searchDelegate: Required<SearchDelegateConfig> | undefined
  readonly hmacKey: Buffer
  readonly fleet: ResolvedFleet
  readonly extensionName: string
  readonly extensionUid: number | undefined
  readonly extensionPlacement: ExtensionPlacement
  readonly vendorName: string
}

/** Resolve the digest key, failing at load rather than producing guessable digests. */
function resolveHmacKey(config: Config, env: NodeJS.ProcessEnv): Buffer {
  const source = config.hmacKey?.source ?? 'ephemeral'
  if (source === 'ephemeral') return randomBytes(MIN_HMAC_KEY_BYTES)
  if (source === 'literal') {
    const value = config.hmacKey?.value
    if (value === undefined || Buffer.byteLength(value) < MIN_HMAC_KEY_BYTES) {
      throw new PolicyError(`hmacKey.value must be at least ${MIN_HMAC_KEY_BYTES} bytes for source "literal"`)
    }
    return Buffer.from(value)
  }
  const variable = config.hmacKey?.variable
  if (variable === undefined) throw new PolicyError('hmacKey.variable is required for source "env"')
  const value = env[variable]
  if (value === undefined || Buffer.byteLength(value) < MIN_HMAC_KEY_BYTES) {
    throw new PolicyError(`environment variable "${variable}" must hold an HMAC key of at least ${MIN_HMAC_KEY_BYTES} bytes`)
  }
  return Buffer.from(value)
}

/** Parse the opened private ranges, refusing the ones no deployment may open. */
function resolveOpenedAddresses(entries: readonly string[]): readonly Cidr[] {
  return entries.map((entry) => {
    const cidr = parseCidr(entry)
    if (cidr === undefined) throw new PolicyError(`allowPrivateAddresses entry "${entry}" is not a CIDR block`)
    const forbidden = overlapsUnopenable(cidr)
    if (forbidden !== undefined) {
      throw new PolicyError(
        `allowPrivateAddresses entry "${entry}" overlaps ${forbidden.source}, which holds cloud instance metadata`
        + ' and link-local addresses; those are never reachable through this plugin',
      )
    }
    return cidr
  })
}

/** Name of the install uid file under the harness home. */
const INSTALL_UID_NAME = 'install-uid'

/** The uid one file holds, or `undefined` when there is none there to read. */
function readInstallUid(path: string): string | undefined {
  let text: string
  try {
    text = readFileSync(path, 'utf8')
  } catch {
    // Any read failure: absent on first run, and unreadable is the same
    // answer — this process has no persisted uid at that path.
    return undefined
  }
  const uid = text.trim()
  return uid.length === 0 ? undefined : uid
}

/**
 * Read the persisted install uid, minting one on first run.
 *
 * A hostname is not an identity: it changes when a laptop is renamed and
 * collides across a fleet built from one image. The uid lives under the harness
 * home rather than beside this plugin's spool so that `dsh-ocsf-forwarder`,
 * whose spool is elsewhere, reports the same `device.uid` for this machine.
 *
 * Persisting it is best effort. A directory this process cannot write is a
 * reason for records to carry a per-process uid, not a reason to refuse the
 * mount — that is the outage `SpoolSink.write` deliberately refuses to cause,
 * and failing here would cause it one step earlier.
 * @param path - where the uid is kept.
 * @param legacyPath - where releases up to 0.1.0 kept it, carried over so an
 *   upgrade does not re-identify the host; `undefined` when the deployment
 *   named the path itself.
 * @param onFailure - notified when the uid cannot be persisted.
 * @returns the uid this installation reports as `device.uid`.
 */
export function readOrCreateInstallUid(
  path: string,
  legacyPath: string | undefined,
  onFailure: (error: unknown) => void = () => {},
): string {
  const persisted = readInstallUid(path)
  if (persisted !== undefined) return persisted
  const uid = (legacyPath === undefined ? undefined : readInstallUid(legacyPath)) ?? randomUUID()
  try {
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(path, `${uid}\n`, { mode: 0o640 })
  } catch (error: unknown) {
    onFailure(error)
  }
  return uid
}

/** Validate one positive finite limit. */
function assertPositive(name: string, value: number): number {
  if (!Number.isFinite(value) || value <= 0) throw new PolicyError(`${name} must be a positive finite number`)
  return value
}

/**
 * Validate one configured path.
 *
 * A relative path resolves against the process's working directory, which for
 * `dsh` is the workspace — the same attacker-controlled directory the
 * repo-local policy tier is defended against. An audit sink inside it can be
 * read, replaced or deleted by the agent it is recording.
 */
function assertAbsolutePath(name: string, value: string): string {
  if (!isAbsolute(value)) {
    throw new PolicyError(
      `${name} must be an absolute path; "${value}" resolves against the workspace, which this plugin treats as`
      + ' attacker-controlled',
    )
  }
  return value
}

/** Resolve the search delegate, which needs both a module and an export to be usable. */
function resolveSearchDelegate(delegate: SearchDelegateConfig | undefined): Required<SearchDelegateConfig> | undefined {
  if (delegate?.module === undefined) {
    if (delegate?.export !== undefined) {
      throw new PolicyError('search.delegate.export needs search.delegate.module beside it')
    }
    return undefined
  }
  if (delegate.export === undefined) {
    throw new PolicyError('search.delegate.module needs search.delegate.export naming the provider class')
  }
  return { module: delegate.module, export: delegate.export, options: { ...delegate.options } }
}

/**
 * Merge the deployment config with an optional repo-local policy.
 * @param config - the deployment-controlled configuration.
 * @param repo - the repo-local policy, when one is mounted.
 * @param env - the process environment, read for an `env`-sourced HMAC key.
 * @param onFailure - notified when the install uid cannot be persisted; `apply`
 *   passes the plugin's reporter, and a caller without one loses only the
 *   uid's stability across restarts.
 * @returns the effective policy every seam reads.
 * @throws PolicyError when any part of the configuration cannot be used as written.
 */
export function resolvePolicy(
  config: Config,
  repo?: RepoPolicy,
  env: NodeJS.ProcessEnv = process.env,
  onFailure: (error: unknown) => void = () => {},
): ResolvedPolicy {
  const fetchConfig = config.fetch ?? {}
  const spoolPath = assertAbsolutePath('spoolPath', config.spoolPath)
  const labels = [...config.fleet?.labels ?? []]
  const tags = Object.entries(config.fleet?.tags ?? {}).map(([name, value]) => ({ name, value }))
  return {
    mode: repo?.enforce === true ? 'enforce' : config.mode ?? 'audit',
    hosts: HostPolicy.compile(config.allow ?? [], [...config.deny ?? [], ...repo?.addDeny ?? []]),
    openedAddresses: resolveOpenedAddresses(config.allowPrivateAddresses ?? []),
    spoolPath,
    hostMemoryPath: config.hostMemoryPath === undefined
      ? `${spoolPath}.hosts`
      : assertAbsolutePath('hostMemoryPath', config.hostMemoryPath),
    fetchProviderId: config.fetchProviderId ?? DEFAULT_PROVIDER_ID,
    searchProviderId: config.searchProviderId ?? DEFAULT_PROVIDER_ID,
    fetch: {
      enabled: fetchConfig.enabled ?? true,
      maxUrlLength: assertPositive('fetch.maxUrlLength', fetchConfig.maxUrlLength ?? DEFAULT_MAX_URL_LENGTH),
      maxResponseBytes: assertPositive('fetch.maxResponseBytes', fetchConfig.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES),
      maxBodyChars: assertPositive('fetch.maxBodyChars', fetchConfig.maxBodyChars ?? DEFAULT_MAX_BODY_CHARS),
      timeoutMs: assertPositive('fetch.timeoutMs', fetchConfig.timeoutMs ?? DEFAULT_TIMEOUT_MS),
      maxRedirects: (() => {
        const value = fetchConfig.maxRedirects ?? DEFAULT_MAX_REDIRECTS
        if (!Number.isInteger(value) || value < 0) throw new PolicyError('fetch.maxRedirects must be a non-negative integer')
        return value
      })(),
      userAgent: fetchConfig.userAgent ?? DEFAULT_USER_AGENT,
    },
    searchEnabled: config.search?.enabled ?? true,
    searchMaxQueryLength: assertPositive(
      'search.maxQueryLength',
      config.search?.maxQueryLength ?? DEFAULT_MAX_QUERY_LENGTH,
    ),
    searchDelegate: resolveSearchDelegate(config.search?.delegate),
    hmacKey: resolveHmacKey(config, env),
    fleet: {
      tenantUid: config.fleet?.tenantUid,
      labels: labels.length === 0 ? undefined : labels,
      tags: tags.length === 0 ? undefined : tags,
      installUid: config.fleet?.installUid
        ?? (config.fleet?.installUidPath === undefined
          ? readOrCreateInstallUid(
            join(resolveDshHome(env), INSTALL_UID_NAME),
            `${spoolPath}.install-uid`,
            onFailure,
          )
          : readOrCreateInstallUid(
            assertAbsolutePath('fleet.installUidPath', config.fleet.installUidPath),
            undefined,
            onFailure,
          )),
    },
    extensionName: config.extension?.name ?? 'dsh',
    extensionUid: config.extension?.uid,
    extensionPlacement: config.extension?.placement ?? 'unmapped',
    vendorName: config.vendorName ?? DEFAULT_VENDOR_NAME,
  }
}
