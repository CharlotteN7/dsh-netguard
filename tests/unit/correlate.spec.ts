/** The two joins: call position from the session firehose, and URL to tool call. */

import { describe, expect, it } from 'vitest'
import { CallCorrelator, TargetCorrelator } from '../../src/correlate.ts'

describe('remembering where a call sits in the session', () => {
  it('reports the turn and step a tool/call event carried', () => {
    const calls = new CallCorrelator()

    calls.note('call-1', { turn: 3, step: 5 })

    expect(calls.lookup('call-1')).toEqual({ turn: 3, step: 5 })
    expect(calls.lookup('call-2')).toBeUndefined()
  })

  it('forgets a call once its result lands', () => {
    const calls = new CallCorrelator()
    calls.note('call-1', { turn: 1, step: 1 })

    calls.forget('call-1')

    expect(calls.lookup('call-1')).toBeUndefined()
  })

  it('drops the oldest entry past its limit, so a long session cannot grow it without bound', () => {
    const calls = new CallCorrelator(2)

    calls.note('a', { turn: 1, step: 1 })
    calls.note('b', { turn: 1, step: 2 })
    calls.note('c', { turn: 1, step: 3 })

    expect(calls.lookup('a')).toBeUndefined()
    expect(calls.lookup('c')).toEqual({ turn: 1, step: 3 })
  })
})

describe('remembering which call asked for a URL', () => {
  const identity = { toolName: 'web_fetch', callId: 'call-1' }

  it('reports the call a URL belongs to', () => {
    const targets = new TargetCorrelator()

    targets.note('https://example.com/', identity)

    expect(targets.lookup('https://example.com/')).toBe(identity)
    expect(targets.lookup('https://elsewhere.test/')).toBeUndefined()
  })

  it('keeps the entry, because one call may produce several requests through redirects', () => {
    const targets = new TargetCorrelator()
    targets.note('https://example.com/', identity)

    targets.lookup('https://example.com/')

    expect(targets.lookup('https://example.com/')).toBe(identity)
  })

  it('drops the oldest entry past its limit', () => {
    const targets = new TargetCorrelator(2)

    targets.note('a', identity)
    targets.note('b', identity)
    targets.note('c', identity)

    expect(targets.lookup('a')).toBeUndefined()
    expect(targets.lookup('c')).toBe(identity)
  })

  it('refreshes an entry re-noted, so a URL fetched repeatedly is not the first evicted', () => {
    const targets = new TargetCorrelator(2)
    targets.note('a', identity)
    targets.note('b', identity)

    targets.note('a', identity)
    targets.note('c', identity)

    expect(targets.lookup('a')).toBe(identity)
    expect(targets.lookup('b')).toBeUndefined()
  })
})
