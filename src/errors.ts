/**
 * The two error types this package throws.
 *
 * {@link PolicyError} is a configuration fault: a malformed pattern, a
 * repo-local file that tries to loosen the policy, an unopenable address range.
 * It fires at load.
 *
 * {@link NetguardWebError} is a refused request, and its `code` mirrors the
 * `ctx.web` seam's own vocabulary so a caller routing on `WEB_BLOCKED_URL`
 * keeps working. It deliberately does NOT extend the harness's `WebError`: that
 * class lives in `@deepseek-ai/dsh-web`, which this package imports with
 * `import type` only. A plugin installed under
 * `$DSH_HOME/profiles/<name>/node_modules` cannot resolve the harness packages
 * from there, so a runtime import of the seam would make the plugin fail to
 * load. The cost is that the tool registry's structured `{ name, code }` error
 * metadata — which it attaches for `HarnessError` instances — is absent; the
 * denial reason still reaches the model in the error message, which is the
 * channel the model reads.
 * @module dsh-netguard/errors
 */

/** Thrown when configuration cannot be used as written. */
export class PolicyError extends Error {
  /**
   * @param message - what the configuration did and why it is refused.
   */
  constructor(message: string) {
    super(`dsh-netguard policy: ${message}`)
    this.name = 'PolicyError'
  }
}

/** Thrown when a request is refused; `code` mirrors the `ctx.web` seam's codes. */
export class NetguardWebError extends Error {
  /** Machine-routable failure class; route on this, never by parsing `message`. */
  readonly code: string

  /**
   * @param message - the model-facing explanation, carrying the denial reason.
   * @param code - the seam-compatible failure class.
   * @param options - standard error options, used for `cause`.
   */
  constructor(message: string, code: string, options?: ErrorOptions) {
    super(message, options)
    this.code = code
    this.name = 'NetguardWebError'
  }
}
