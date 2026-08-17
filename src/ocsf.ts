/**
 * OCSF Network Activity (4001) records, with the `security_control` profile.
 *
 * Every identifier here was read from `https://schema.ocsf.io/api/1.9.0/...`
 * and is an external specification, not a deployment choice: none of it is
 * configurable. `type_uid` is derived, never stored.
 *
 * How the three outcomes map:
 *
 * | Outcome | `activity_id` | `action_id` | `disposition_id` | `severity_id` |
 * |---|---|---|---|---|
 * | allowed | 1 Open | 1 Allowed | 1 Allowed | 1 Informational |
 * | denied, `mode: enforce` | 5 Refuse | 2 Denied | 2 Blocked | 3 Medium |
 * | denied, `mode: audit` | 1 Open | 1 Allowed | 17 Logged | 3 Medium |
 *
 * The audit row is the one that needs saying out loud: in audit mode the
 * connection **was made**, so the record says Open and Allowed. `disposition_id: 17`
 * (Logged) and `unmapped.dsh.enforced: false` are what tell a SOC that the
 * policy would have refused it. A record that claimed Refuse for a request that
 * completed would be a false negative in the only direction that matters.
 *
 * The correlation key is `dsh-ocsf-forwarder`'s, unchanged:
 * `metadata.correlation_uid = <session>:<callId>`. Stamping the forwarder's own
 * correlation key onto these records is what answers *which tool call opened
 * this connection*.
 *
 * The idempotency key is deliberately not: `metadata.uid` is
 * `<session>:netguard:<seq>`, where `seq` counts this package's decisions.
 * The forwarder's is `<session>:<seq>` over the session log's own event
 * sequence, so both packages would otherwise emit `session-88:4` for unrelated
 * events and a SIEM told to deduplicate on `metadata.uid` would drop one of
 * them. See ADR.md §18.
 * @module dsh-netguard/ocsf
 */

import { hostname, platform, userInfo } from 'node:os'
import type { ResolvedPolicy } from './policy.ts'
import type { DenialReason } from './reasons.ts'

/** The OCSF schema version every emitted record declares in `metadata.version`. */
export const OCSF_VERSION = '1.9.0'

/** This plugin's name, reported in `metadata.product.name`. */
export const PRODUCT_NAME = 'dsh-netguard'

/** Name reported as the agent runtime in `metadata.log_provider` and `src_endpoint.svc_name`. */
export const AGENT_NAME = 'deepseek-harness'

/** Network Activity; the only class this package emits. */
export const CLASS_NETWORK_ACTIVITY = 4001

/** `category_uid` of Network Activity. */
export const CATEGORY_NETWORK = 4

/** Class-specific `activity_id` values used here. */
export const ACTIVITY = Object.freeze({ open: 1, refuse: 5 })

/** `action_id` values of the `security_control` profile. */
export const ACTION = Object.freeze({ allowed: 1, denied: 2 })

/** `disposition_id` values of the `security_control` profile. */
export const DISPOSITION = Object.freeze({ allowed: 1, blocked: 2, logged: 17 })

/** `severity_id` values of the base event. */
export const SEVERITY = Object.freeze({ informational: 1, medium: 3 })

/** `connection_info.direction_id`: every request this package sees leaves the host. */
const DIRECTION_OUTBOUND = 2

/** `observable.type_id` values this package emits. */
const OBSERVABLE = Object.freeze({ hostname: 1, ipAddress: 2 })

/**
 * Profiles every record declares, one per profile-owned attribute it carries.
 * Under `additionalProperties: false` an undeclared profile's attribute is
 * exactly the validation failure the declaration exists to avoid.
 */
const RECORD_PROFILES: readonly string[] = Object.freeze(['security_control', 'host'])

/** Version of the extension-owned attribute object, independent of the harness log format. */
export const DSH_ATTRIBUTES_VERSION = 1

/**
 * Middle segment of `metadata.uid`, which keeps this package's idempotency keys
 * out of the space `dsh-ocsf-forwarder` numbers from the session log.
 */
export const UID_NAMESPACE = 'netguard'

/** A JSON value, as a record carries it. */
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue }

/** One finished record, ready to serialize. */
export type OcsfRecord = Record<string, JsonValue>

/** Per-process identity shared by every record. */
export interface RecordEnvironment {
  readonly policy: ResolvedPolicy
  readonly productVersion: string
  readonly device: JsonValue
  readonly srcEndpoint: JsonValue
  /** Injectable so tests get deterministic `metadata.logged_time`. */
  readonly now: () => number
}

/**
 * Build the per-process identity every record shares.
 * @param policy - the resolved policy, for the fleet identity and vendor name.
 * @param productVersion - this plugin's version, reported in `metadata.product`.
 * @param now - clock used for `metadata.logged_time` and `time`.
 * @returns the shared record environment.
 */
export function createEnvironment(
  policy: ResolvedPolicy,
  productVersion: string,
  now: () => number = Date.now,
): RecordEnvironment {
  const host = hostname()
  return {
    policy,
    productVersion,
    // `device.uid` is the stable install identity: a renamed laptop keeps it,
    // and two hosts imaged from one template do not share it.
    device: {
      type_id: 0,
      hostname: host,
      uid: policy.fleet.installUid,
      os: { name: platform(), type_id: 0 },
      owner: { name: userInfo().username, type_id: 1 },
    },
    srcEndpoint: { hostname: host, svc_name: AGENT_NAME },
    now,
  }
}

/** Which arm of the plugin produced one record. */
export type DecisionKind = 'fetch' | 'redirect' | 'search' | 'guard'

/** Everything one decision contributes to its record. */
export interface DecisionInput {
  readonly kind: DecisionKind
  /** What the policy decided, before `mode` is applied. */
  readonly verdict: 'allowed' | 'denied'
  /** False when `mode: audit` let a denied request through. */
  readonly enforced: boolean
  readonly reason?: DenialReason | undefined
  /** The matched rule id, exactly as `hosts.ts` or `decide.ts` reported it. */
  readonly rule?: string | undefined
  readonly host: string
  readonly port: number
  readonly scheme?: string | undefined
  /** The address the socket was pinned to, once one was chosen. */
  readonly resolvedIp?: string | undefined
  /** True the first time this installation has seen the host. */
  readonly firstSeen: boolean
  readonly toolName?: string | undefined
  readonly sessionId?: string | undefined
  readonly callId?: string | undefined
  readonly rootCallId?: string | undefined
  readonly turn?: number | undefined
  readonly step?: number | undefined
  readonly decisionId: string
  /** Monotonic per-process counter; the second half of `metadata.uid`. */
  readonly seq: number
  /** Extra extension-owned attributes: digests, hop counts, dropped-source counts. */
  readonly attributes?: Readonly<Record<string, JsonValue>>
}

/** Drop `undefined`-valued keys so the serialized record has no empty slots. */
function compact(value: Readonly<Record<string, JsonValue | undefined>>): Record<string, JsonValue> {
  return Object.fromEntries(Object.entries(value).filter((entry): entry is [string, JsonValue] => entry[1] !== undefined))
}

/** The three profile-owned outcome ids, derived from the verdict and whether it was applied. */
export function outcomeIds(input: Pick<DecisionInput, 'verdict' | 'enforced'>): {
  activityId: number
  actionId: number
  dispositionId: number
  severityId: number
} {
  if (input.verdict === 'allowed') {
    return {
      activityId: ACTIVITY.open,
      actionId: ACTION.allowed,
      dispositionId: DISPOSITION.allowed,
      severityId: SEVERITY.informational,
    }
  }
  if (input.enforced) {
    return {
      activityId: ACTIVITY.refuse,
      actionId: ACTION.denied,
      dispositionId: DISPOSITION.blocked,
      severityId: SEVERITY.medium,
    }
  }
  return {
    activityId: ACTIVITY.open,
    actionId: ACTION.allowed,
    dispositionId: DISPOSITION.logged,
    severityId: SEVERITY.medium,
  }
}

/**
 * Compose one OCSF Network Activity record.
 * @param env - the per-process identity.
 * @param input - the decision.
 * @returns a complete OCSF 1.9.0 record.
 */
export function buildDecisionRecord(env: RecordEnvironment, input: DecisionInput): OcsfRecord {
  const { policy } = env
  const { activityId, actionId, dispositionId, severityId } = outcomeIds(input)
  const time = env.now()
  const attributes: Record<string, JsonValue> = compact({
    v: DSH_ATTRIBUTES_VERSION,
    kind: input.kind,
    mode: policy.mode,
    verdict: input.verdict,
    enforced: input.enforced,
    reason: input.reason,
    rule: input.rule,
    tool: input.toolName,
    session_id: input.sessionId,
    call_id: input.callId,
    root_call_id: input.rootCallId,
    turn: input.turn,
    step: input.step,
    decision_id: input.decisionId,
    first_seen_host: input.firstSeen,
    ...input.attributes,
  })
  const observables: JsonValue[] = [
    { name: 'dst_endpoint.hostname', type_id: OBSERVABLE.hostname, value: input.host },
    ...input.resolvedIp === undefined
      ? []
      : [{ name: 'dst_endpoint.ip', type_id: OBSERVABLE.ipAddress, value: input.resolvedIp }],
  ]
  return compact({
    class_uid: CLASS_NETWORK_ACTIVITY,
    category_uid: CATEGORY_NETWORK,
    type_uid: CLASS_NETWORK_ACTIVITY * 100 + activityId,
    activity_id: activityId,
    action_id: actionId,
    disposition_id: dispositionId,
    severity_id: severityId,
    status_id: input.verdict === 'allowed' ? 1 : 2,
    // A host this installation has never contacted is what an operator wants
    // paged on, in either mode; a refusal is the routine case once a policy is
    // in force.
    is_alert: input.firstSeen || (input.verdict === 'denied' && !input.enforced),
    time,
    message: input.verdict === 'allowed'
      ? `netguard allowed ${input.host}`
      : `netguard ${input.enforced ? 'refused' : 'recorded'} ${input.host}: ${String(input.reason)}`,
    metadata: compact({
      product: { name: PRODUCT_NAME, vendor_name: policy.vendorName, version: env.productVersion },
      version: OCSF_VERSION,
      profiles: [...RECORD_PROFILES],
      // `metadata.extension` is deprecated; the list is omitted entirely until a
      // deployment supplies a uid the OCSF registry assigned it.
      extensions: policy.extensionUid === undefined
        ? undefined
        : [{ name: policy.extensionName, uid: policy.extensionUid, version: env.productVersion }],
      log_provider: AGENT_NAME,
      log_name: 'netguard',
      uid: `${input.sessionId ?? PRODUCT_NAME}:${UID_NAMESPACE}:${String(input.seq)}`,
      correlation_uid: input.callId === undefined || input.sessionId === undefined
        ? undefined
        : `${input.sessionId}:${input.callId}`,
      sequence: input.seq,
      logged_time: time,
      tenant_uid: policy.fleet.tenantUid,
      labels: policy.fleet.labels === undefined ? undefined : [...policy.fleet.labels],
      tags: policy.fleet.tags === undefined ? undefined : policy.fleet.tags.map(tag => ({ ...tag })),
    }),
    device: env.device,
    src_endpoint: env.srcEndpoint,
    dst_endpoint: compact({
      hostname: input.host,
      port: input.port,
      ip: input.resolvedIp,
      svc_name: input.scheme,
    }),
    connection_info: { direction_id: DIRECTION_OUTBOUND, protocol_name: 'tcp' },
    firewall_rule: input.rule === undefined
      ? undefined
      : compact({ uid: input.rule, name: input.reason ?? 'allow' }),
    observables,
    ...policy.extensionPlacement === 'unmapped'
      ? { unmapped: { [policy.extensionName]: attributes } }
      : { [policy.extensionName]: attributes },
  })
}
