/** Body classification and decoding, kept identical to the shipped provider's. */

import { describe, expect, it } from 'vitest'
import { classifyContentType, decoderForCharset, parseCharset } from '../../src/content.ts'

describe('classifying a content type', () => {
  it.each([
    ['text/html', 'html'],
    ['text/html; charset=utf-8', 'html'],
    ['application/xhtml+xml', 'html'],
    ['TEXT/HTML', 'html'],
    ['text/plain', 'text'],
    ['text/markdown; charset=utf-8', 'text'],
    ['application/json', 'text'],
    ['application/xml', 'text'],
    ['application/ld+json', 'text'],
    ['image/svg+xml', 'text'],
  ])('reads %s as %s', (header, expected) => {
    expect(classifyContentType(header)).toBe(expected)
  })

  it.each([
    ['image/png'],
    ['application/octet-stream'],
    ['application/pdf'],
  ])('refuses %s, which it cannot decode', (header) => {
    expect(classifyContentType(header)).toBeUndefined()
  })

  it('refuses a response with no content type at all', () => {
    expect(classifyContentType(undefined)).toBeUndefined()
  })
})

describe('reading a charset', () => {
  it.each([
    ['text/plain; charset=UTF-8', 'utf-8'],
    ['text/html;charset="iso-8859-1"', 'iso-8859-1'],
    ['text/plain ; charset = latin1 ; x=1', 'latin1'],
  ])('reads %s as %s', (header, expected) => {
    expect(parseCharset(header)).toBe(expected)
  })

  it('reports no charset when none is declared', () => {
    expect(parseCharset('text/plain')).toBeUndefined()
    expect(parseCharset(undefined)).toBeUndefined()
  })
})

describe('building a decoder', () => {
  it('defaults to UTF-8', () => {
    expect(decoderForCharset(undefined).encoding).toBe('utf-8')
  })

  it('uses the declared encoding', () => {
    expect(decoderForCharset('iso-8859-1').encoding).toBe('windows-1252')
  })

  it('fails loud on a label it does not know, rather than returning mojibake', () => {
    expect(() => decoderForCharset('made-up-9')).toThrow(/unsupported charset/)
  })
})
