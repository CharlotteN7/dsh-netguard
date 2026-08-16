/** The closed refusal vocabulary and the sentence each reason produces. */

import { describe, expect, it } from 'vitest'
import { denialMessage, DENIAL_REASONS, REASON_CODES } from '../../src/reasons.ts'

describe('the refusal vocabulary', () => {
  it('is closed: every reason has a code and nothing else does', () => {
    expect([...DENIAL_REASONS].sort()).toEqual(Object.keys(REASON_CODES).sort())
    expect(DENIAL_REASONS).toEqual([
      'blocked-by-allowlist',
      'blocked-by-denylist',
      'blocked-by-private-address',
      'blocked-by-scheme',
      'blocked-by-credentials',
      'blocked-by-redirect',
      'blocked-by-url-length',
      'blocked-by-invalid-url',
      'blocked-by-invalid-argument',
      'blocked-by-query-length',
    ])
  })

  it('maps each reason to a code the ctx.web seam already uses', () => {
    expect(new Set(Object.values(REASON_CODES)))
      .toEqual(new Set(['WEB_BLOCKED_URL', 'WEB_INVALID_URL', 'WEB_REDIRECT_BLOCKED']))
  })
})

describe('the message a refusal returns to the model', () => {
  it('names the host, the reason, the rule, and what to do about it', () => {
    expect(denialMessage('blocked-by-denylist', 'paste.example:8443', 'deny:paste.example'))
      .toBe(
        'dsh-netguard refused this request to paste.example:8443: blocked-by-denylist'
        + ' (rule deny:paste.example). This host is denied explicitly and cannot be reached from this agent.',
      )
  })

  it('omits the rule when no pattern decided it', () => {
    const message = denialMessage('blocked-by-allowlist', 'paste.example')

    expect(message).not.toContain('rule')
    expect(message).toContain('Ask the user to add the host')
  })

  it.each(DENIAL_REASONS)('carries advice for %s', (reason) => {
    const message = denialMessage(reason, 'example.com')

    expect(message).toContain(reason)
    // Every reason ends in a sentence telling the model what it can change.
    expect(message.split('. ').at(-1)?.length).toBeGreaterThan(20)
  })
})
