/** The OCSF 4001 record: outcome ids, the declared profile, and the identity scheme. */

import { afterAll, describe, expect, it } from 'vitest'
import { buildDecisionRecord, createEnvironment, outcomeIds, type DecisionInput } from '../../src/ocsf.ts'
import { disposeHome, makeHome, policyOf } from './support.ts'

const home = makeHome('ocsf')
afterAll(() => { disposeHome(home) })

/** One record built over a policy, with the fields a test cares about. */
function record(input: Partial<DecisionInput> = {}, policyOverrides = {}) {
  const policy = policyOf(home, { allow: ['*'], ...policyOverrides })
  const env = createEnvironment(policy, '0.1.0', () => 1_700_000_000_000)
  return buildDecisionRecord(env, {
    kind: 'fetch',
    verdict: 'allowed',
    enforced: true,
    host: 'example.com',
    port: 443,
    scheme: 'https',
    firstSeen: false,
    decisionId: 'netguard-fixture',
    seq: 1,
    ...input,
  })
}

/** The extension-owned attributes of one record. */
function dsh(built: ReturnType<typeof record>): Record<string, unknown> {
  return (built['unmapped'] as { dsh: Record<string, unknown> }).dsh
}

describe('the outcome ids', () => {
  it('reports an allowed request as Open / Allowed / Allowed', () => {
    expect(outcomeIds({ verdict: 'allowed', enforced: true }))
      .toEqual({ activityId: 1, actionId: 1, dispositionId: 1, severityId: 1 })
  })

  it('reports an enforced denial as Refuse / Denied / Blocked', () => {
    expect(outcomeIds({ verdict: 'denied', enforced: true }))
      .toEqual({ activityId: 5, actionId: 2, dispositionId: 2, severityId: 3 })
  })

  it('reports an audit-mode denial as Open / Allowed / Logged, because the connection was made', () => {
    expect(outcomeIds({ verdict: 'denied', enforced: false }))
      .toEqual({ activityId: 1, actionId: 1, dispositionId: 17, severityId: 3 })
  })
})

describe('the record', () => {
  it('is a Network Activity record with a derived type_uid', () => {
    const built = record()

    expect(built).toMatchObject({ class_uid: 4001, category_uid: 4, type_uid: 400_101, activity_id: 1 })
  })

  it('declares exactly the profiles whose attributes it carries', () => {
    expect((record()['metadata'] as { profiles: string[] }).profiles).toEqual(['security_control', 'host'])
  })

  it('carries the destination endpoint verbatim and the URL only as a digest', () => {
    const built = record({
      resolvedIp: '198.51.100.34',
      attributes: { url_digest: 'hmac-sha256:abcd', url_length: 42, has_query: true },
    })

    expect(built['dst_endpoint']).toEqual({
      hostname: 'example.com',
      port: 443,
      ip: '198.51.100.34',
      svc_name: 'https',
    })
    expect(JSON.stringify(built)).not.toContain('https://example.com/secret')
    expect(dsh(built)['url_digest']).toBe('hmac-sha256:abcd')
  })

  it('uses the forwarder\'s correlation key, so the two packages join', () => {
    const built = record({ sessionId: 'session-7', callId: 'call-3', seq: 9 })
    const metadata = built['metadata'] as Record<string, unknown>

    expect(metadata['correlation_uid']).toBe('session-7:call-3')
  })

  it('namespaces metadata.uid, because the forwarder numbers session events into the same space', () => {
    const metadata = record({ sessionId: 'session-7', callId: 'call-3', seq: 9 })['metadata'] as Record<string, unknown>

    // `session-7:9` is the forwarder's key for the ninth event of that session,
    // an unrelated record a SIEM deduplicating on this field would drop.
    expect(metadata['uid']).toBe('session-7:netguard:9')
  })

  it('falls back to the product name in metadata.uid when no session is known', () => {
    const metadata = record({ callId: 'call-3' })['metadata'] as Record<string, unknown>

    expect(metadata['uid']).toBe('dsh-netguard:netguard:1')
    expect(metadata['correlation_uid']).toBeUndefined()
  })

  it('alerts on a first-seen host and on an audit-mode denial, and on nothing else', () => {
    expect(record({ firstSeen: true })['is_alert']).toBe(true)
    expect(record({ verdict: 'denied', enforced: false, reason: 'blocked-by-allowlist' })['is_alert']).toBe(true)
    expect(record({ verdict: 'denied', enforced: true, reason: 'blocked-by-allowlist' })['is_alert']).toBe(false)
    expect(record()['is_alert']).toBe(false)
  })

  it('names the matched rule as a firewall rule', () => {
    expect(record({ verdict: 'denied', enforced: true, reason: 'blocked-by-denylist', rule: 'deny:evil.test' })['firewall_rule'])
      .toEqual({ uid: 'deny:evil.test', name: 'blocked-by-denylist' })
    expect(record()['firewall_rule']).toBeUndefined()
  })

  it('omits the extension list until a deployment has a registered uid', () => {
    expect((record()['metadata'] as Record<string, unknown>)['extensions']).toBeUndefined()
    expect((record({}, { extension: { uid: 999 } })['metadata'] as { extensions: unknown[] }).extensions)
      .toEqual([{ name: 'dsh', uid: 999, version: '0.1.0' }])
  })

  it('stamps the fleet identity a deployment configured', () => {
    const metadata = record({}, {
      fleet: { installUid: 'install-1', tenantUid: 'acme', labels: ['ci'], tags: { team: 'sec' } },
    })['metadata'] as Record<string, unknown>

    expect(metadata['tenant_uid']).toBe('acme')
    expect(metadata['labels']).toEqual(['ci'])
    expect(metadata['tags']).toEqual([{ name: 'team', value: 'sec' }])
  })

  it('places the attributes at the top level when a deployment asks for that', () => {
    const built = record({}, { extension: { name: 'acme', placement: 'attribute' } })

    expect(built['unmapped']).toBeUndefined()
    expect((built['acme'] as Record<string, unknown>)['verdict']).toBe('allowed')
  })

  it('records the mode, the verdict and whether it was applied', () => {
    const built = record({ verdict: 'denied', enforced: false, reason: 'blocked-by-allowlist' }, { mode: 'audit' })

    expect(dsh(built)).toMatchObject({ mode: 'audit', verdict: 'denied', enforced: false, reason: 'blocked-by-allowlist' })
    expect(built['message']).toBe('netguard recorded example.com: blocked-by-allowlist')
  })

  it('lists the host and the resolved address as observables', () => {
    expect(record({ resolvedIp: '198.51.100.34' })['observables']).toEqual([
      { name: 'dst_endpoint.hostname', type_id: 1, value: 'example.com' },
      { name: 'dst_endpoint.ip', type_id: 2, value: '198.51.100.34' },
    ])
    expect(record()['observables']).toHaveLength(1)
  })

  it('reports the install uid as the device identity', () => {
    expect((record()['device'] as Record<string, unknown>)['uid']).toBe('install-fixture')
  })

  it('says the connection is outbound', () => {
    expect(record()['connection_info']).toEqual({ direction_id: 2, protocol_name: 'tcp' })
  })
})
