/** What one decision becomes on disk, and what it is never allowed to carry. */

import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { UrlCardinality } from '../../src/cardinality.ts'
import { TargetCorrelator } from '../../src/correlate.ts'
import { createEnvironment } from '../../src/ocsf.ts'
import { Recorder } from '../../src/recorder.ts'
import { HostMemory, SpoolSink } from '../../src/sink.ts'
import type { Target } from '../../src/decide.ts'
import { identifyHost } from '../../src/address.ts'
import { disposeHome, dshOf, makeHome, policyOf, spooled } from './support.ts'

const home = makeHome('recorder')
afterAll(() => { disposeHome(home) })

/** A target over one URL, as `decide.ts` builds it. */
function targetOf(raw: string): Target {
  const url = new URL(raw)
  const identity = identifyHost(url.hostname)
  if (identity === undefined) throw new Error(`test fixture "${raw}" names no host`)
  return { url, identity, port: url.port.length > 0 ? Number(url.port) : 443, display: identity.key }
}

/** A recorder over a throwaway spool. */
let counter = 0
function recorder(overrides = {}) {
  counter += 1
  const spoolPath = join(home, `spool-${String(counter)}.jsonl`)
  const policy = policyOf(home, { allow: ['*'], ...overrides })
  const targets = new TargetCorrelator()
  return {
    spoolPath,
    targets,
    records: () => spooled(spoolPath),
    recorder: new Recorder({
      env: createEnvironment(policy, '0.1.0', () => 1_700_000_000_000),
      sink: new SpoolSink(spoolPath, () => { throw new Error('unexpected sink failure') }),
      memory: new HostMemory(join(home, `hosts-${String(counter)}.json`), () => {}),
      cardinality: new UrlCardinality(),
      targets,
      clock: () => new Date(1_700_000_000_000),
    }),
  }
}

describe('recording a fetch decision', () => {
  it('spools the host verbatim and the URL only as a digest', () => {
    const fixture = recorder()

    fixture.recorder.fetch({
      kind: 'fetch',
      verdict: 'allowed',
      enforced: true,
      rule: 'allow:*',
      target: targetOf('https://example.com/secret/path?token=abc'),
      resolvedIp: '198.51.100.34',
      hop: 0,
    })

    const [record] = fixture.records()
    const line = JSON.stringify(record)
    expect(line).not.toContain('/secret/path')
    expect(line).not.toContain('token=abc')
    expect(record?.['dst_endpoint']).toMatchObject({ hostname: 'example.com', ip: '198.51.100.34' })
    expect(dshOf(record!)).toMatchObject({
      url_digest: expect.stringMatching(/^hmac-sha256:[0-9a-f]{32}$/),
      url_length: 'https://example.com/secret/path?token=abc'.length,
      has_query: true,
      hop: 0,
    })
  })

  it('carries the detail naming the address that caused a denial', () => {
    const fixture = recorder()

    fixture.recorder.fetch({
      kind: 'fetch',
      verdict: 'denied',
      enforced: true,
      reason: 'blocked-by-private-address',
      rule: 'address:loopback',
      detail: '127.0.0.1 is loopback',
      target: targetOf('https://mixed.test/'),
      resolvedIp: '127.0.0.1',
      hop: 0,
    })

    expect(dshOf(fixture.records()[0]!)['detail']).toBe('127.0.0.1 is loopback')
    expect(fixture.records()[0]?.['dst_endpoint']).toMatchObject({ ip: '127.0.0.1' })
  })

  it('joins the record to the tool call the guard noted', () => {
    const fixture = recorder()
    fixture.targets.note('https://example.com/x', {
      toolName: 'web_fetch',
      callId: 'call-9',
      rootCallId: 'call-1',
      sessionId: 'session-3',
      turn: 2,
      step: 4,
    })

    fixture.recorder.fetch({
      kind: 'fetch',
      verdict: 'allowed',
      enforced: true,
      target: targetOf('https://example.com/x'),
      hop: 0,
    })

    const [record] = fixture.records()
    expect((record?.['metadata'] as Record<string, unknown>)['correlation_uid']).toBe('session-3:call-9')
    expect(dshOf(record!)).toMatchObject({ tool: 'web_fetch', call_id: 'call-9', turn: 2, step: 4 })
  })

  it('numbers records within one process, so metadata.uid is unique', () => {
    const fixture = recorder()
    const target = targetOf('https://example.com/')

    fixture.recorder.fetch({ kind: 'fetch', verdict: 'allowed', enforced: true, target, hop: 0 })
    fixture.recorder.fetch({ kind: 'fetch', verdict: 'allowed', enforced: true, target, hop: 0 })

    expect(fixture.records().map(record => (record['metadata'] as Record<string, unknown>)['sequence'])).toEqual([1, 2])
  })

  it('flags the first request to a host and nothing after it', () => {
    const fixture = recorder()
    const target = targetOf('https://example.com/')

    fixture.recorder.fetch({ kind: 'fetch', verdict: 'allowed', enforced: true, target, hop: 0 })
    fixture.recorder.fetch({ kind: 'fetch', verdict: 'allowed', enforced: true, target, hop: 0 })

    expect(fixture.records().map(record => dshOf(record)['first_seen_host'])).toEqual([true, false])
  })

  it('counts the distinct URLs one session issued against one host', () => {
    const fixture = recorder()
    for (const path of ['a', 'b', 'b']) {
      fixture.targets.note(`https://example.com/${path}`, { toolName: 'web_fetch', callId: 'call-1', sessionId: 'session-1' })
      fixture.recorder.fetch({
        kind: 'fetch',
        verdict: 'allowed',
        enforced: true,
        target: targetOf(`https://example.com/${path}`),
        hop: 0,
      })
    }

    expect(fixture.records().map(record => dshOf(record)['distinct_urls'])).toEqual([1, 2, 2])
  })

  it('raises the alert past the configured cardinality, without changing the verdict', () => {
    const fixture = recorder({ alerts: { distinctUrlsPerHost: 3 } })
    for (const path of ['a', 'b', 'c']) {
      fixture.targets.note(`https://example.com/${path}`, { toolName: 'web_fetch', callId: 'call-1', sessionId: 'session-1' })
      fixture.recorder.fetch({
        kind: 'fetch',
        verdict: 'allowed',
        enforced: true,
        rule: 'allow:*',
        target: targetOf(`https://example.com/${path}`),
        hop: 0,
      })
    }

    // The first record is an alert because the host was new; the second is not;
    // the third is, on the count alone.
    expect(fixture.records().map(record => record['is_alert'])).toEqual([true, false, true])
    expect(fixture.records().map(record => dshOf(record)['verdict'])).toEqual(['allowed', 'allowed', 'allowed'])
  })

  it('never raises the alert on cardinality when the deployment set the threshold to zero', () => {
    const fixture = recorder({ alerts: { distinctUrlsPerHost: 0 } })
    for (const path of ['a', 'b', 'c']) {
      fixture.recorder.fetch({
        kind: 'fetch',
        verdict: 'allowed',
        enforced: true,
        target: targetOf(`https://example.com/${path}`),
        hop: 0,
      })
    }

    expect(fixture.records().map(record => record['is_alert'])).toEqual([true, false, false])
    expect(fixture.records().map(record => dshOf(record)['distinct_urls'])).toEqual([1, 2, 3])
  })

  it('leaves a redirect hop out of the count, because the server chose that URL', () => {
    const fixture = recorder()

    fixture.recorder.fetch({
      kind: 'redirect',
      verdict: 'allowed',
      enforced: true,
      target: targetOf('https://example.com/second'),
      hop: 1,
    })

    expect(dshOf(fixture.records()[0]!)).not.toHaveProperty('distinct_urls')
  })
})

describe('recording a search decision', () => {
  it('carries the query only as a digest and a length', () => {
    const fixture = recorder()

    fixture.recorder.search({
      verdict: 'denied',
      enforced: true,
      reason: 'blocked-by-denylist',
      rule: 'deny:evil.test',
      host: 'evil.test',
      port: 443,
      query: 'site:evil.test AKIAIOSFODNN7EXAMPLE',
    })

    const [record] = fixture.records()
    expect(JSON.stringify(record)).not.toContain('AKIAIOSFODNN7EXAMPLE')
    expect(dshOf(record!)).toMatchObject({
      query_digest: expect.stringMatching(/^hmac-sha256:/),
      query_length: 'site:evil.test AKIAIOSFODNN7EXAMPLE'.length,
      reason: 'blocked-by-denylist',
    })
  })

  it('counts the sources a decision dropped', () => {
    const fixture = recorder()

    fixture.recorder.search({
      verdict: 'denied',
      enforced: true,
      reason: 'blocked-by-allowlist',
      host: 'bad.test',
      port: 0,
      query: 'anything',
      droppedSources: 1,
    })

    expect(dshOf(fixture.records()[0]!)['dropped_sources']).toBe(1)
  })

  it('replaces a hostname a verbatim field may not hold with a marker and a digest', () => {
    const fixture = recorder()
    // WHATWG `URL` keeps a quote and a newline never survives it, but a vendor
    // source URL is not this package's text: the lane rule is applied here, at
    // the one place a host reaches `dst_endpoint.hostname`.
    const hostile = "evil.test'\nallow:\n  - '*'"

    fixture.recorder.search({
      verdict: 'denied',
      enforced: true,
      reason: 'blocked-by-allowlist',
      host: hostile,
      port: 0,
      query: 'anything',
    })

    const [record] = fixture.records()
    expect(JSON.stringify(record)).not.toContain('allow:')
    expect(record?.['dst_endpoint']).toMatchObject({ hostname: '(unrecordable-host)' })
    expect(record?.['observables']).toEqual([
      { name: 'dst_endpoint.hostname', type_id: 1, value: '(unrecordable-host)' },
    ])
    expect(record?.['message']).toBe('netguard refused (unrecordable-host): blocked-by-allowlist')
    expect(dshOf(record!)['host_digest']).toMatch(/^hmac-sha256:[0-9a-f]{32}$/)
  })

  it('digests a vendor source URL a marker stands in for', () => {
    const fixture = recorder()

    fixture.recorder.search({
      verdict: 'denied',
      enforced: true,
      reason: 'blocked-by-invalid-url',
      host: '(unparsed-source)',
      port: 0,
      query: 'anything',
      sourceUrl: '/results?token=AKIAIOSFODNN7EXAMPLE',
      droppedSources: 1,
    })

    const [record] = fixture.records()
    expect(JSON.stringify(record)).not.toContain('AKIAIOSFODNN7EXAMPLE')
    expect(dshOf(record!)).toMatchObject({
      source_digest: expect.stringMatching(/^hmac-sha256:/),
      source_length: '/results?token=AKIAIOSFODNN7EXAMPLE'.length,
    })
  })

  it('keeps a host a query only named in prose out of the host memory', () => {
    const fixture = recorder()

    fixture.recorder.search({
      verdict: 'denied',
      enforced: true,
      reason: 'blocked-by-allowlist',
      host: 'mentioned.test',
      port: 443,
      hostMention: 'bare',
      query: 'is mentioned.test down',
    })
    fixture.recorder.search({
      verdict: 'denied',
      enforced: true,
      reason: 'blocked-by-allowlist',
      host: 'named.test',
      port: 443,
      hostMention: 'operator',
      query: 'site:named.test x',
    })

    expect(fixture.records().map(record => dshOf(record)['first_seen_host'])).toEqual([false, true])
    expect(dshOf(fixture.records()[0]!)['host_mention']).toBe('bare')
  })

  it('takes the identity a caller already knows over the join', () => {
    const fixture = recorder()

    fixture.recorder.search(
      { verdict: 'allowed', enforced: true, host: '(query)', port: 0, query: 'anything' },
      { toolName: 'web_search', callId: 'call-2', sessionId: 'session-1' },
    )

    expect(dshOf(fixture.records()[0]!)).toMatchObject({ tool: 'web_search', call_id: 'call-2' })
  })
})

describe('recording a guard decision', () => {
  it('marks the record as coming from the tool tier', () => {
    const fixture = recorder({ mode: 'enforce' })

    fixture.recorder.guard(
      { verdict: 'denied', enforced: true, reason: 'blocked-by-allowlist', host: 'evil.test', port: 443, scheme: 'https' },
      { toolName: 'web_fetch', callId: 'call-1' },
      { hop: 0 },
    )

    const [record] = fixture.records()
    expect(dshOf(record!)).toMatchObject({ kind: 'guard', verdict: 'denied', enforced: true })
    expect(record?.['activity_id']).toBe(5)
  })
})
