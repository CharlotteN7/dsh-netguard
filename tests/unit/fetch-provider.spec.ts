/**
 * The guarded fetch provider, against real loopback servers.
 *
 * Loopback is a refused address, so every test that expects a connection opens
 * it explicitly through `allowPrivateAddresses` — which is also what makes the
 * connect-time tests below possible: `127.0.0.1/32` is open and `127.0.0.2` is
 * not, so a resolver that changes its answer between the two is a rebinding a
 * test can observe.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { identifyHost, type HostIdentity } from '../../src/address.ts'
import { NetguardWebError } from '../../src/errors.ts'
import {
  GuardedFetchProvider,
  pinnedLookup,
  remoteAddressMismatch,
  systemResolver,
  translateTransportError,
  type FetchObservation,
  type Resolver,
} from '../../src/fetch-provider.ts'
import type { Config } from '../../src/policy.ts'
import { disposeHome, makeHome, policyOf } from './support.ts'

const home = makeHome('fetch')
const servers: Server[] = []

afterEach(async () => {
  await Promise.all(servers.splice(0).map(async server => await new Promise<void>(resolve => server.close(() => { resolve() }))))
})
afterAll(() => { disposeHome(home) })

/** Identify a host the tests know is well formed. */
function host(text: string): HostIdentity {
  const identity = identifyHost(text)
  if (identity === undefined) throw new Error(`test fixture "${text}" is not a host`)
  return identity
}

/** One loopback server, with a record of the requests it received. */
interface Fixture {
  readonly port: number
  readonly origin: string
  readonly requests: string[]
}

/** Start a server on one loopback address and remember its requests. */
async function serve(
  handler: (request: IncomingMessage, response: ServerResponse) => void,
  address = '127.0.0.1',
): Promise<Fixture> {
  const requests: string[] = []
  const server = createServer((request, response) => {
    requests.push(request.url ?? '')
    handler(request, response)
  })
  servers.push(server)
  await new Promise<void>(resolve => server.listen(0, address, resolve))
  const port = (server.address() as AddressInfo).port
  return { port, origin: `http://${address}:${String(port)}`, requests }
}

/** A provider over a policy that opens `127.0.0.1` only. */
function provider(overrides: Partial<Config> = {}, resolve?: Resolver) {
  const observations: FetchObservation[] = []
  const policy = policyOf(home, {
    mode: 'enforce',
    allow: ['*'],
    allowPrivateAddresses: ['127.0.0.1/32'],
    ...overrides,
  })
  return {
    observations,
    policy,
    fetch: new GuardedFetchProvider({
      id: 'dsh-netguard',
      policy,
      observe: observation => { observations.push(observation) },
      ...resolve === undefined ? {} : { resolve },
    }),
  }
}

/** A handler answering with one body and content type. */
function replies(body: string, contentType = 'text/plain'): (request: IncomingMessage, response: ServerResponse) => void {
  return (_request, response) => {
    response.writeHead(200, { 'content-type': contentType })
    response.end(body)
  }
}

describe('a permitted request', () => {
  it('is retrieved and reported as allowed', async () => {
    const fixture = await serve(replies('hello'))
    const guard = provider()

    const result = await guard.fetch.fetch({ url: `${fixture.origin}/page` })

    expect(result).toMatchObject({
      statusCode: 200,
      body: { kind: 'text', content: 'hello' },
      truncated: false,
    })
    expect(guard.observations.map(entry => [entry.kind, entry.verdict, entry.resolvedIp])).toEqual([
      ['fetch', 'allowed', undefined],
      ['fetch', 'allowed', '127.0.0.1'],
    ])
  })

  it('reports the provider as available and under its configured id', () => {
    const guard = provider()

    expect(guard.fetch.id).toBe('dsh-netguard')
    expect(guard.fetch.available()).toBe(true)
  })

  it('decodes html as html', async () => {
    const fixture = await serve(replies('<p>hi</p>', 'text/html; charset=utf-8'))

    const result = await provider().fetch.fetch({ url: `${fixture.origin}/` })

    expect(result.body).toEqual({ kind: 'html', content: '<p>hi</p>' })
  })

  it('carries no compression negotiation, so the byte cap sees what the socket delivered', async () => {
    let encoding: string | undefined
    const fixture = await serve((request, response) => {
      encoding = request.headers['accept-encoding']
      response.writeHead(200, { 'content-type': 'text/plain' })
      response.end('ok')
    })

    await provider().fetch.fetch({ url: `${fixture.origin}/` })

    expect(encoding).toBe('identity')
  })

  it('sends the configured user agent and no cookies', async () => {
    let headers: IncomingMessage['headers'] | undefined
    const fixture = await serve((request, response) => {
      headers = request.headers
      response.writeHead(200, { 'content-type': 'text/plain' })
      response.end('ok')
    })

    await provider({ fetch: { userAgent: 'test-agent/1' } }).fetch.fetch({ url: `${fixture.origin}/` })

    expect(headers?.['user-agent']).toBe('test-agent/1')
    expect(headers?.cookie).toBeUndefined()
  })

  it('returns a non-2xx response as a result rather than an error', async () => {
    const fixture = await serve((_request, response) => {
      response.writeHead(404, { 'content-type': 'text/plain' })
      response.end('gone')
    })

    expect(await provider().fetch.fetch({ url: `${fixture.origin}/` })).toMatchObject({ statusCode: 404 })
  })
})

describe('a refused request', () => {
  it('never opens a socket', async () => {
    const fixture = await serve(replies('secret'))
    const guard = provider({ allow: [] })

    await expect(guard.fetch.fetch({ url: `${fixture.origin}/page` })).rejects.toThrow(/blocked-by-allowlist/)
    expect(fixture.requests).toEqual([])
  })

  it('carries the reason, the rule, and a seam-compatible code', async () => {
    const fixture = await serve(replies('secret'))
    const guard = provider({ allow: ['*'], deny: ['127.0.0.1'] })

    const error = await guard.fetch.fetch({ url: `${fixture.origin}/` }).catch((thrown: unknown) => thrown)

    expect(error).toBeInstanceOf(NetguardWebError)
    expect((error as NetguardWebError).code).toBe('WEB_BLOCKED_URL')
    expect((error as Error).message).toContain('blocked-by-denylist')
    expect((error as Error).message).toContain('rule deny:127.0.0.1')
  })

  it('refuses a resolved address the deployment did not open', async () => {
    const fixture = await serve(replies('internal'), '127.0.0.2')
    const guard = provider()

    await expect(guard.fetch.fetch({ url: `${fixture.origin}/` }))
      .rejects.toThrow(/blocked-by-private-address/)
    expect(fixture.requests).toEqual([])
  })

  it.each([
    ['a scheme that is not http(s)', 'ws://127.0.0.1/socket', /blocked-by-scheme/],
    ['credentials in the URL', 'http://user:pass@127.0.0.1/', /blocked-by-credentials/],
  ])('refuses %s', async (_label, url, expected) => {
    await expect(provider().fetch.fetch({ url })).rejects.toThrow(expected)
  })

  it('reports a URL it cannot parse as an invalid URL, not as a policy denial', async () => {
    const guard = provider()

    await expect(guard.fetch.fetch({ url: 'not a url' })).rejects.toMatchObject({ code: 'WEB_INVALID_URL' })
    expect(guard.observations).toEqual([])
  })
})

describe('audit mode', () => {
  it('records the denial and lets the request through', async () => {
    const fixture = await serve(replies('hello'))
    const guard = provider({ mode: 'audit', allow: [] })

    const result = await guard.fetch.fetch({ url: `${fixture.origin}/page` })

    expect(result.body).toEqual({ kind: 'text', content: 'hello' })
    expect(fixture.requests).toEqual(['/page'])
    expect(guard.observations[0]).toMatchObject({ verdict: 'denied', enforced: false, reason: 'blocked-by-allowlist' })
  })

  it('records a refused address and still connects to it', async () => {
    const fixture = await serve(replies('internal'), '127.0.0.2')
    const guard = provider({ mode: 'audit' })

    await guard.fetch.fetch({ url: `${fixture.origin}/` })

    expect(fixture.requests).toEqual(['/'])
    expect(guard.observations[1]).toMatchObject({
      verdict: 'denied',
      enforced: false,
      reason: 'blocked-by-private-address',
      resolvedIp: '127.0.0.2',
    })
  })
})

describe('redirects', () => {
  it('follows a same-origin hop and re-checks it', async () => {
    const fixture = await serve((request, response) => {
      if (request.url === '/one') {
        response.writeHead(302, { location: '/two' })
        response.end()
        return
      }
      response.writeHead(200, { 'content-type': 'text/plain' })
      response.end('arrived')
    })
    const guard = provider()

    const result = await guard.fetch.fetch({ url: `${fixture.origin}/one` })

    expect(result).toMatchObject({ url: `${fixture.origin}/two`, body: { content: 'arrived' } })
    expect(fixture.requests).toEqual(['/one', '/two'])
    expect(guard.observations.map(entry => entry.kind)).toEqual(['fetch', 'fetch', 'redirect', 'redirect'])
  })

  it('refuses a cross-origin hop, so each origin needs its own tool call', async () => {
    const elsewhere = await serve(replies('elsewhere'), '127.0.0.2')
    const fixture = await serve((_request, response) => {
      response.writeHead(302, { location: `${elsewhere.origin}/` })
      response.end()
    })

    await expect(provider().fetch.fetch({ url: `${fixture.origin}/` })).rejects.toThrow(/blocked-by-redirect/)
    expect(elsewhere.requests).toEqual([])
  })

  it('refuses a hop past the budget', async () => {
    const fixture = await serve((_request, response) => {
      response.writeHead(302, { location: '/next' })
      response.end()
    })

    await expect(provider({ fetch: { maxRedirects: 2 } }).fetch.fetch({ url: `${fixture.origin}/` }))
      .rejects.toThrow(/exceeded 2 hops/)
    expect(fixture.requests).toHaveLength(3)
  })

  it('refuses a Location that is not a reference at all', async () => {
    const fixture = await serve((_request, response) => {
      response.writeHead(302, { location: 'http://' })
      response.end()
    })

    await expect(provider().fetch.fetch({ url: `${fixture.origin}/` })).rejects.toThrow(/unparseable Location/)
  })

  it('reports a redirect status with no Location as a provider error', async () => {
    const fixture = await serve((_request, response) => {
      response.writeHead(302)
      response.end()
    })

    await expect(provider().fetch.fetch({ url: `${fixture.origin}/` }))
      .rejects.toMatchObject({ code: 'WEB_PROVIDER_ERROR' })
  })

  it('re-checks the path grant on every hop, so an allowed path is no open redirector', async () => {
    // Same origin, so the shipped provider's cross-origin rule does not catch
    // this one: only re-running the path decision per hop does.
    const fixture = await serve((request, response) => {
      if (request.url === '/org/repo') {
        response.writeHead(302, { location: '/admin' })
        response.end()
        return
      }
      response.writeHead(200, { 'content-type': 'text/plain' })
      response.end('secret')
    })
    const guard = provider(
      { allow: [`scoped.test:${String(fixture.port)}/org/repo`] },
      async () => [{ address: '127.0.0.1', family: 4 }],
    )

    await expect(guard.fetch.fetch({ url: `http://scoped.test:${String(fixture.port)}/org/repo` }))
      .rejects.toThrow(/blocked-by-allowlist/)
    expect(fixture.requests).toEqual(['/org/repo'])
    expect(guard.observations.at(-1)).toMatchObject({ kind: 'redirect', verdict: 'denied', hop: 1 })
  })

  it('refuses every hop when the budget is zero', async () => {
    const fixture = await serve((_request, response) => {
      response.writeHead(302, { location: '/next' })
      response.end()
    })

    await expect(provider({ fetch: { maxRedirects: 0 } }).fetch.fetch({ url: `${fixture.origin}/` }))
      .rejects.toThrow(/exceeded 0 hops/)
  })
})

describe('bounding what comes back', () => {
  it('refuses a body whose declared length is over the cap', async () => {
    const fixture = await serve((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/plain', 'content-length': '5000' })
      response.end('x'.repeat(5000))
    })

    await expect(provider({ fetch: { maxResponseBytes: 100 } }).fetch.fetch({ url: `${fixture.origin}/` }))
      .rejects.toMatchObject({ code: 'WEB_FETCH_TOO_LARGE' })
  })

  it('cuts a stream that grows past the cap rather than failing it', async () => {
    const fixture = await serve((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/plain' })
      response.write('a'.repeat(80))
      response.end('b'.repeat(80))
    })

    const result = await provider({ fetch: { maxResponseBytes: 100 } }).fetch.fetch({ url: `${fixture.origin}/` })

    expect(result.truncated).toBe(true)
    expect(result.body.content).toHaveLength(100)
  })

  it('does not flag a body that exactly fills the cap', async () => {
    const fixture = await serve(replies('x'.repeat(100)))

    const result = await provider({ fetch: { maxResponseBytes: 100 } }).fetch.fetch({ url: `${fixture.origin}/` })

    expect(result.truncated).toBe(false)
  })

  it('cuts a decoded body past the character cap', async () => {
    const fixture = await serve(replies('y'.repeat(50)))

    const result = await provider({ fetch: { maxBodyChars: 10 } }).fetch.fetch({ url: `${fixture.origin}/` })

    expect(result).toMatchObject({ truncated: true, body: { content: 'y'.repeat(10) } })
  })

  it('refuses a content type it cannot decode', async () => {
    const fixture = await serve(replies(' binary', 'image/png'))

    await expect(provider().fetch.fetch({ url: `${fixture.origin}/` }))
      .rejects.toMatchObject({ code: 'WEB_UNSUPPORTED_CONTENT_TYPE' })
  })

  it('refuses a charset it cannot decode rather than returning mojibake', async () => {
    const fixture = await serve(replies('text', 'text/plain; charset=made-up-9'))

    await expect(provider().fetch.fetch({ url: `${fixture.origin}/` }))
      .rejects.toMatchObject({ code: 'WEB_UNSUPPORTED_CONTENT_TYPE' })
  })

  it('decodes a declared non-UTF-8 charset with that charset', async () => {
    const fixture = await serve((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/plain; charset=latin1' })
      response.end(Buffer.from([0xe9]))
    })

    expect((await provider().fetch.fetch({ url: `${fixture.origin}/` })).body.content).toBe('é')
  })
})

describe('cancellation', () => {
  it('refuses an already-aborted signal without touching the network', async () => {
    const fixture = await serve(replies('hello'))

    await expect(provider().fetch.fetch({ url: `${fixture.origin}/` }, AbortSignal.abort()))
      .rejects.toMatchObject({ code: 'WEB_ABORTED' })
    expect(fixture.requests).toEqual([])
  })

  it('reports the caller\'s abort as an abort', async () => {
    const fixture = await serve(() => {
      // Never answers: the abort below is what ends the request.
    })
    const controller = new AbortController()
    const pending = provider().fetch.fetch({ url: `${fixture.origin}/` }, controller.signal)
    setTimeout(() => { controller.abort() }, 20)

    await expect(pending).rejects.toMatchObject({ code: 'WEB_ABORTED' })
  })

  it('reports its own deadline as a timeout', async () => {
    const fixture = await serve(() => {
      // Never answers, so the provider's own timeout is what fires.
    })

    await expect(provider({ fetch: { timeoutMs: 50 } }).fetch.fetch({ url: `${fixture.origin}/` }))
      .rejects.toMatchObject({ code: 'WEB_FETCH_TIMEOUT' })
  })

  it('reports a transport failure as a provider error', async () => {
    const fixture = await serve(replies('hello'))
    const closedPort = fixture.port
    await new Promise<void>(resolve => servers.splice(servers.indexOf(servers[0] as Server), 1)[0]?.close(() => { resolve() }))

    await expect(provider().fetch.fetch({ url: `http://127.0.0.1:${String(closedPort)}/` }))
      .rejects.toMatchObject({ code: 'WEB_PROVIDER_ERROR' })
  })
})

describe('connect-time enforcement', () => {
  it('drives the connection from the vetted answer, not from the system resolver', async () => {
    // `pinned.test` has no DNS record anywhere. The request can only arrive if
    // the socket followed the lookup hook this provider installed.
    const fixture = await serve(replies('pinned'))
    const guard = provider(
      { allow: [`pinned.test:${String(fixture.port)}`] },
      async () => [{ address: '127.0.0.1', family: 4 }],
    )

    const result = await guard.fetch.fetch({ url: `http://pinned.test:${String(fixture.port)}/page` })

    expect(result.body.content).toBe('pinned')
    expect(fixture.requests).toEqual(['/page'])
  })

  it('refuses a name whose answer changes between the check and the connect', async () => {
    // The rebinding: the first answer is a public address the policy permits,
    // and every later answer is the loopback server the attacker wants reached.
    // A pre-check would pass and a re-resolving connect would land on the
    // server; a pinned socket goes to the checked address and never arrives.
    const target = await serve(replies('internal'))
    let calls = 0
    const rebinding: Resolver = async () => {
      calls += 1
      return calls === 1 ? [{ address: '203.0.113.7', family: 4 }] : [{ address: '127.0.0.1', family: 4 }]
    }
    const guard = provider(
      { allow: [`rebind.test:${String(target.port)}`], fetch: { timeoutMs: 1500 } },
      rebinding,
    )

    const error = await guard.fetch
      .fetch({ url: `http://rebind.test:${String(target.port)}/steal` })
      .catch((thrown: unknown) => thrown)

    expect(error).toBeInstanceOf(NetguardWebError)
    expect(['WEB_FETCH_TIMEOUT', 'WEB_PROVIDER_ERROR']).toContain((error as NetguardWebError).code)
    expect(target.requests).toEqual([])
    // The resolver was consulted once. The second answer never reached a socket.
    expect(calls).toBe(1)
    expect(guard.observations.at(-1)).toMatchObject({ verdict: 'allowed', resolvedIp: '203.0.113.7' })
  })

  it('re-resolves each redirect hop, so a hop to a rebound answer is refused', async () => {
    let calls = 0
    const fixture = await serve((request, response) => {
      if (request.url === '/one') {
        response.writeHead(302, { location: '/two' })
        response.end()
        return
      }
      response.writeHead(200, { 'content-type': 'text/plain' })
      response.end('arrived')
    })
    const rebinding: Resolver = async () => {
      calls += 1
      return calls === 1 ? [{ address: '127.0.0.1', family: 4 }] : [{ address: '169.254.169.254', family: 4 }]
    }
    const guard = provider({ allow: [`hop.test:${String(fixture.port)}`] }, rebinding)

    await expect(guard.fetch.fetch({ url: `http://hop.test:${String(fixture.port)}/one` }))
      .rejects.toThrow(/blocked-by-private-address/)
    expect(fixture.requests).toEqual(['/one'])
  })

  it('names the address that caused the denial, not the first one the resolver returned', async () => {
    // The record that exists to catch a rebinding has to point at the endpoint
    // that was refused; `addresses[0]` is the one that was fine.
    const guard = provider(
      { allow: ['mixed.test'] },
      async () => [{ address: '203.0.113.7', family: 4 }, { address: '169.254.169.254', family: 4 }],
    )

    await expect(guard.fetch.fetch({ url: 'http://mixed.test/' })).rejects.toThrow(/blocked-by-private-address/)
    expect(guard.observations.at(-1)).toMatchObject({
      verdict: 'denied',
      rule: 'address:cloud-metadata',
      resolvedIp: '169.254.169.254',
      detail: '169.254.169.254 is cloud-metadata',
    })
  })

  it('reports a resolver failure as a provider error', async () => {
    const guard = provider({ allow: ['broken.test'] }, async () => { throw new Error('SERVFAIL') })

    await expect(guard.fetch.fetch({ url: 'http://broken.test/' }))
      .rejects.toMatchObject({ code: 'WEB_PROVIDER_ERROR' })
  })

  it('treats an answer of nothing usable as an answer of nothing', async () => {
    const guard = provider({ allow: ['odd.test'] }, async () => [{ address: 'not-an-address', family: 4 }])

    await expect(guard.fetch.fetch({ url: 'http://odd.test/' }))
      .rejects.toThrow(/blocked-by-private-address/)
    expect(guard.observations.at(-1)).toMatchObject({ verdict: 'denied' })
    expect(guard.observations.at(-1)?.resolvedIp).toBeUndefined()
  })

  it('cannot connect to an empty answer even in audit mode', async () => {
    const guard = provider({ mode: 'audit', allow: ['empty.test'] }, async () => [])

    await expect(guard.fetch.fetch({ url: 'http://empty.test/' }))
      .rejects.toMatchObject({ code: 'WEB_PROVIDER_ERROR' })
    expect(guard.observations.at(-1)).toMatchObject({ verdict: 'denied', enforced: false })
  })

  it('skips resolution entirely when the URL already names an address', async () => {
    const fixture = await serve(replies('literal'))
    let calls = 0
    const guard = provider({}, async () => { calls += 1; return [{ address: '127.0.0.1', family: 4 }] })

    await guard.fetch.fetch({ url: `${fixture.origin}/` })

    expect(calls).toBe(0)
  })
})

describe('verifying the address the socket reached', () => {
  it('accepts the vetted address, in either of the spellings a kernel reports it', () => {
    expect(remoteAddressMismatch('127.0.0.1', host('127.0.0.1'))).toBe(false)
    expect(remoteAddressMismatch('::ffff:127.0.0.1', host('127.0.0.1'))).toBe(false)
  })

  it('abstains while the socket is still connecting', () => {
    expect(remoteAddressMismatch(undefined, host('127.0.0.1'))).toBe(false)
  })

  it.each([
    ['a different address', '127.0.0.2'],
    ['a different family', '::1'],
    ['text that is not an address', 'somewhere'],
  ])('rejects %s', (_label, remote) => {
    expect(remoteAddressMismatch(remote, host('127.0.0.1'))).toBe(true)
  })
})

describe('the default resolver', () => {
  it('asks the system for every address of a name', async () => {
    const answers = await systemResolver('localhost')

    expect(answers.length).toBeGreaterThan(0)
    expect(answers.every(answer => identifyHost(answer.address) !== undefined)).toBe(true)
  })
})

describe('the lookup hook', () => {
  it('answers with the vetted address in the list shape net.connect asks for', () => {
    const answers: unknown[] = []
    pinnedLookup(host('127.0.0.1'))('ignored.test', { all: true }, ((...args: unknown[]) => { answers.push(args) }) as never)

    expect(answers).toEqual([[null, [{ address: '127.0.0.1', family: 4 }]]])
  })

  it('answers with the vetted address in the single-address shape', () => {
    const answers: unknown[] = []
    pinnedLookup(host('[::1]'))('ignored.test', {}, ((...args: unknown[]) => { answers.push(args) }) as never)

    expect(answers).toEqual([[null, '::1', 6]])
  })
})

describe('classifying a transport failure', () => {
  it('keeps a refusal this package already raised', () => {
    const refusal = new NetguardWebError('refused', 'WEB_BLOCKED_URL')

    expect(translateTransportError(refusal, new AbortController().signal, new AbortController().signal)).toBe(refusal)
  })

  it('reports our own deadline as a timeout, ahead of the caller\'s abort', () => {
    expect(translateTransportError(new Error('socket hang up'), AbortSignal.abort(), AbortSignal.abort()))
      .toMatchObject({ code: 'WEB_FETCH_TIMEOUT' })
  })

  it('reports the caller\'s abort as an abort', () => {
    expect(translateTransportError(new Error('x'), AbortSignal.abort(), new AbortController().signal))
      .toMatchObject({ code: 'WEB_ABORTED' })
  })

  it('reports anything else as a provider error', () => {
    const live = new AbortController().signal

    expect(translateTransportError(new Error('ECONNRESET'), live, live)).toMatchObject({ code: 'WEB_PROVIDER_ERROR' })
  })
})

describe('the transport', () => {
  it('speaks TLS for an https URL, which a plain HTTP server cannot answer', async () => {
    const fixture = await serve(replies('plain'))

    await expect(provider().fetch.fetch({ url: `https://127.0.0.1:${String(fixture.port)}/` }))
      .rejects.toMatchObject({ code: 'WEB_PROVIDER_ERROR' })
  })

  it('connects to an IPv6 literal target', async () => {
    const fixture = await serve(replies('six'), '::1')
    const guard = provider({ allow: ['*'], allowPrivateAddresses: ['::1/128'] })

    const result = await guard.fetch.fetch({ url: `http://[::1]:${String(fixture.port)}/` })

    expect(result.body.content).toBe('six')
    expect(guard.observations.at(-1)).toMatchObject({ resolvedIp: '::1' })
  })

  it('follows a resolver answer that is an IPv6 address', async () => {
    const fixture = await serve(replies('six'), '::1')
    const guard = provider(
      { allow: [`six.test:${String(fixture.port)}`], allowPrivateAddresses: ['::1/128'] },
      async () => [{ address: '::1', family: 6 }],
    )

    expect((await guard.fetch.fetch({ url: `http://six.test:${String(fixture.port)}/` })).body.content).toBe('six')
  })

  it('refuses a response that declares no content type', async () => {
    const fixture = await serve((_request, response) => {
      response.writeHead(200)
      response.end('body')
    })

    await expect(provider().fetch.fetch({ url: `${fixture.origin}/` }))
      .rejects.toThrow(/unsupported content type "unknown"/)
  })

  it('reports a connection dropped mid-body as a provider error', async () => {
    const fixture = await serve((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/plain', 'content-length': '100' })
      response.write('partial')
      response.socket?.destroy()
    })

    await expect(provider().fetch.fetch({ url: `${fixture.origin}/` }))
      .rejects.toMatchObject({ code: 'WEB_PROVIDER_ERROR' })
  })

  it('reports an abort that lands mid-body as an abort', async () => {
    const fixture = await serve((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/plain', 'content-length': '100' })
      response.write('partial')
      // The rest never arrives, so the read is still open when the abort lands.
    })
    const controller = new AbortController()
    const pending = provider().fetch.fetch({ url: `${fixture.origin}/` }, controller.signal)
    setTimeout(() => { controller.abort() }, 30)

    await expect(pending).rejects.toMatchObject({ code: 'WEB_ABORTED' })
  })

  it('reports a resolver that failed after the caller aborted as an abort', async () => {
    const controller = new AbortController()
    const guard = provider({ allow: ['slow.test'] }, async () => {
      controller.abort()
      throw new Error('resolution cancelled')
    })

    await expect(guard.fetch.fetch({ url: 'http://slow.test/' }, controller.signal))
      .rejects.toMatchObject({ code: 'WEB_ABORTED' })
  })
})
