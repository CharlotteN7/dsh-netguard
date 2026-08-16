/** The spool, the host memory, and what each does when it cannot write. */

import { readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { HostMemory, newDecisionId, readHostMemory, SpoolSink } from '../../src/sink.ts'
import { disposeHome, makeHome, spooled } from './support.ts'

const home = makeHome('sink')
afterAll(() => { disposeHome(home) })

/** A unique path inside the throwaway home. */
let counter = 0
function path(name: string): string {
  counter += 1
  return join(home, `${name}-${String(counter)}`)
}

describe('a decision id', () => {
  it('is unique and names the package that minted it', () => {
    expect(newDecisionId()).toMatch(/^netguard-[0-9a-f-]{36}$/)
    expect(newDecisionId()).not.toBe(newDecisionId())
  })
})

describe('the spool', () => {
  it('appends one line per record and creates the directory it needs', () => {
    const file = join(home, 'nested', 'deeper', 'spool.jsonl')
    const sink = new SpoolSink(file, () => { throw new Error('unexpected failure') })

    sink.write({ class_uid: 4001 })
    sink.write({ class_uid: 4001, activity_id: 5 })

    expect(spooled(file)).toHaveLength(2)
    expect(statSync(file).mode & 0o777).toBe(0o640)
  })

  it('reports a write failure rather than throwing, so a full disk is not a denial', () => {
    const failures: unknown[] = []
    // A directory cannot be appended to, so the write fails while the mount stands.
    const sink = new SpoolSink(home, error => { failures.push(error) })

    sink.write({ class_uid: 4001 })

    expect(failures).toHaveLength(1)
  })

  it('reports a failure to create its directory rather than throwing', () => {
    const file = path('blocking-file')
    writeFileSync(file, 'not a directory')
    const failures: unknown[] = []

    new SpoolSink(join(file, 'spool.jsonl'), error => { failures.push(error) })

    expect(failures).toHaveLength(1)
  })
})

describe('the host memory', () => {
  it('reports a host as new exactly once, and counts what happened after', () => {
    const file = path('hosts.json')
    const memory = new HostMemory(file, () => { throw new Error('unexpected failure') })

    expect(memory.note('example.com', 'allowed', new Date(1_000))).toBe(true)
    expect(memory.note('example.com', 'denied', new Date(2_000))).toBe(false)

    expect([...readHostMemory(file).entries()]).toEqual([[
      'example.com',
      { first: new Date(1_000).toISOString(), last: new Date(2_000).toISOString(), allowed: 1, denied: 1 },
    ]])
  })

  it('survives a restart, so first-seen means first for this installation', () => {
    const file = path('persisted.json')
    new HostMemory(file, () => {}).note('example.com', 'allowed', new Date(1_000))

    expect(new HostMemory(file, () => {}).note('example.com', 'allowed', new Date(2_000))).toBe(false)
    expect(readFileSync(file, 'utf8')).toContain('example.com')
  })

  it('reports a write failure rather than failing the request', () => {
    const failures: unknown[] = []
    const file = path('blocked')
    writeFileSync(file, 'not a directory')
    const memory = new HostMemory(join(file, 'hosts.json'), error => { failures.push(error) })

    memory.note('example.com', 'allowed', new Date(0))

    expect(failures).toHaveLength(1)
  })
})

describe('reading a host-memory file', () => {
  it('starts empty when there is none', () => {
    expect(readHostMemory(path('absent.json')).size).toBe(0)
  })

  it.each([
    ['a torn write', '{"v":1,"hos'],
    ['a version it does not know', '{"v":99,"hosts":{}}'],
    ['a document that is not one', '[]'],
    ['a hosts field that is not a map', '{"v":1,"hosts":null}'],
  ])('starts empty on %s rather than refusing to run', (_label, text) => {
    const file = path('corrupt.json')
    writeFileSync(file, text)

    expect(readHostMemory(file).size).toBe(0)
  })
})
