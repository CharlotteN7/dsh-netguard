/**
 * This package's own version, read from its manifest.
 *
 * Two places carry it: `metadata.product.version` on every record, and the
 * default `User-Agent` the fetch provider sends. A literal in either goes stale
 * at the next release, and a `User-Agent` naming a version this build is not
 * misidentifies the client in the logs of every host the agent contacts. It is
 * its own module because `policy.ts` holds the second one and cannot import
 * `index.ts`, which imports `policy.ts`.
 * @module dsh-netguard/version
 */

import { readFileSync } from 'node:fs'

/**
 * This package's own version.
 * @param base - the module URL the manifest is resolved against.
 * @returns the manifest's version, or `0.0.0` when there is no readable manifest.
 */
export function readPackageVersion(base: string | URL): string {
  let manifest: string
  try {
    manifest = readFileSync(new URL('../package.json', base), 'utf8')
  } catch {
    // ENOENT only: a consumer that vendored the module without its manifest.
    // A record with an odd version beats a plugin that will not mount.
    return '0.0.0'
  }
  return (JSON.parse(manifest) as { version?: string }).version ?? '0.0.0'
}

/** Version reported in `metadata.product.version` and in the default `User-Agent`. */
export const VERSION: string = readPackageVersion(import.meta.url)
