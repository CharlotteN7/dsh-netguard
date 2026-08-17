/** Counting distinct URLs per session and host, inside a fixed memory budget. */

import { describe, expect, it } from 'vitest'
import { UrlCardinality } from '../../src/cardinality.ts'

/** A digest-shaped value; the counter never parses it. */
function digest(index: number): string {
  return `hmac-sha256:${String(index).padStart(32, '0')}`
}

describe('counting distinct URLs', () => {
  it('counts one URL once however often a session asks for it', () => {
    const counter = new UrlCardinality()

    expect(counter.note('session-1', 'example.com', digest(1))).toBe(1)
    expect(counter.note('session-1', 'example.com', digest(1))).toBe(1)
    expect(counter.note('session-1', 'example.com', digest(2))).toBe(2)
  })

  it('counts each host separately, so one busy host does not raise another', () => {
    const counter = new UrlCardinality()

    counter.note('session-1', 'example.com', digest(1))
    counter.note('session-1', 'example.com', digest(2))

    expect(counter.note('session-1', 'other.test', digest(3))).toBe(1)
  })

  it('counts each session separately, so a long-lived install does not accumulate', () => {
    const counter = new UrlCardinality()

    counter.note('session-1', 'example.com', digest(1))

    expect(counter.note('session-2', 'example.com', digest(2))).toBe(1)
  })

  it('puts every request whose session is unknown in one pair per host', () => {
    const counter = new UrlCardinality()

    expect(counter.note(undefined, 'example.com', digest(1))).toBe(1)
    expect(counter.note(undefined, 'example.com', digest(2))).toBe(2)
  })

  it('saturates rather than growing past the per-pair cap', () => {
    const counter = new UrlCardinality({ urlsPerPair: 2 })

    counter.note('session-1', 'example.com', digest(1))
    counter.note('session-1', 'example.com', digest(2))

    expect(counter.note('session-1', 'example.com', digest(3))).toBe(2)
  })

  it('drops the least recently counted pair past the pair cap', () => {
    const counter = new UrlCardinality({ pairs: 2 })

    counter.note('session-1', 'a.test', digest(1))
    counter.note('session-1', 'b.test', digest(2))
    counter.note('session-1', 'c.test', digest(3))

    // `a.test` was evicted, so its count restarts; `c.test` is still held.
    expect(counter.note('session-1', 'a.test', digest(1))).toBe(1)
    expect(counter.note('session-1', 'c.test', digest(4))).toBe(2)
  })

  it('keeps the pair being hammered, which is the one the signal is about', () => {
    const counter = new UrlCardinality({ pairs: 2 })

    counter.note('session-1', 'busy.test', digest(1))
    counter.note('session-1', 'b.test', digest(2))
    counter.note('session-1', 'busy.test', digest(3))
    // Evicts the least recently counted pair, which re-counting `busy.test`
    // moved off the front.
    counter.note('session-1', 'c.test', digest(4))

    expect(counter.note('session-1', 'busy.test', digest(5))).toBe(3)
  })

  it('never lets a session id and a host run together into one pair', () => {
    const counter = new UrlCardinality()

    counter.note('a', 'b c', digest(1))

    // Joined on any single character these two would be the same pair.
    expect(counter.note('a b', 'c', digest(2))).toBe(1)
  })
})
