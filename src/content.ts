/**
 * Response-body classification and decoding, kept identical to the shipped
 * `web-fetch-http` provider so replacing that provider does not change what
 * `web_fetch` returns to the model.
 *
 * These are re-implemented rather than imported: every harness type this
 * package uses is imported with `import type`, so nothing from
 * `@deepseek-ai/dsh-*` is emitted as a runtime import and the plugin can load
 * from a profile's own `node_modules`.
 * @module dsh-netguard/content
 */

import { TextDecoder } from 'node:util'
import { NetguardWebError } from './errors.ts'

/** The body kinds this provider decodes. */
export type FetchableKind = 'html' | 'text'

/**
 * Classify a response `Content-Type` into a decodable body kind.
 * @param contentType - the raw header, or `undefined` when the response carries none.
 * @returns the decodable kind, or `undefined` for an unsupported (binary) type.
 */
export function classifyContentType(contentType: string | undefined): FetchableKind | undefined {
  const mime = (contentType ?? '').replace(/;.*$/s, '').trim().toLowerCase()
  if (mime === 'text/html' || mime === 'application/xhtml+xml') return 'html'
  if (mime.startsWith('text/')) return 'text'
  if (mime === 'application/json' || mime === 'application/xml' || mime.endsWith('+json') || mime.endsWith('+xml')) return 'text'
  return undefined
}

/**
 * Extract the `charset` parameter of a `Content-Type`, lower-cased.
 * @param contentType - the raw header, or `undefined`.
 * @returns the charset label, or `undefined` when none is declared.
 */
export function parseCharset(contentType: string | undefined): string | undefined {
  const match = /;\s*charset\s*=\s*"?([^";]+)"?/i.exec(contentType ?? '')
  return match?.[1]?.trim().toLowerCase()
}

/**
 * Build a decoder for the declared charset, defaulting to UTF-8.
 * @param charset - the declared label, or `undefined`.
 * @returns a decoder for the declared (or defaulted) encoding.
 * @throws NetguardWebError when the label is present but unrecognised — mojibake
 *   that the model would quote as fact is worse than a loud failure.
 */
export function decoderForCharset(charset: string | undefined): TextDecoder {
  if (charset === undefined) return new TextDecoder('utf-8')
  try {
    return new TextDecoder(charset)
  } catch (error: unknown) {
    throw new NetguardWebError(`unsupported charset "${charset}"`, 'WEB_UNSUPPORTED_CONTENT_TYPE', { cause: error })
  }
}
