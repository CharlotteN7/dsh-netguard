/**
 * Where the harness keeps its state, and where this plugin's spool lands by
 * default.
 *
 * Its own module so the `dsh-netguard report` command can resolve the spool
 * without importing the plugin: `policy.ts` pulls in `js-yaml` and the schema
 * library, neither of which a reader of a JSONL file needs.
 * @module dsh-netguard/home
 */

import { homedir } from 'node:os'
import { join, resolve } from 'node:path'

/**
 * Path the bundle patch gives the spool under the harness home.
 * `cordis.patch.yml` spells the same name; a deployment that sets `spoolPath`
 * itself must tell `dsh-netguard report` where it put it.
 */
export const DEFAULT_SPOOL_NAME = join('netguard', 'decisions.ocsf.jsonl')

/**
 * Resolve the harness home the same way the harness does: `$DSH_HOME` when it
 * is set to something other than whitespace, otherwise `~/.dsh`. Read here
 * rather than through `@deepseek-ai/dsh-home-paths` to keep this package's
 * runtime imports to the ones a profile is guaranteed to resolve.
 * @param env - environment consulted for `DSH_HOME`; defaults to `process.env`.
 * @returns the absolute harness home.
 */
export function resolveDshHome(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env['DSH_HOME']
  return resolve(configured !== undefined && configured.trim().length > 0 ? configured : join(homedir(), '.dsh'))
}

/**
 * Where the spool sits when the deployment did not name one.
 * @param env - environment consulted for `DSH_HOME`; defaults to `process.env`.
 * @returns the absolute path the bundle patch configures.
 */
export function defaultSpoolPath(env: NodeJS.ProcessEnv = process.env): string {
  return join(resolveDshHome(env), DEFAULT_SPOOL_NAME)
}
