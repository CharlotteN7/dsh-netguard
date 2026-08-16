# Architecture decisions — dsh-netguard

Decisions that are not obvious from the code, and the evidence behind them.

---

## 1. `node:https` / `node:http`, not global `fetch`

Global `fetch` (undici) **ignores a `lookup` function in `RequestInit`**. Without that hook the
policy check and the connect are two independent name resolutions, and the whole DNS-rebinding
class stays open: a name answers with a public address for the check and with `169.254.169.254`
for the connect. No amount of pre-checking closes it, because the pre-check is not what decides
where the socket goes.

`node:https.request` honours `lookup`, so the resolver is called once, the answer is vetted, and
the socket is pinned to the exact address that was vetted. `socket.remoteAddress` is verified on
`connect` / `secureConnect` as the second half of the same promise.

The cost is that everything `fetch` did for free is owned here: redirect following, the byte
cap, content-type classification, charset decoding. `content.ts` re-implements the shipped
provider's classification so replacing that provider does not change what `web_fetch` returns to
the model.

Two supporting choices:

- **`agent: false`.** A pooled agent may hand back a socket opened earlier for the same
  hostname, to whatever address that earlier resolution produced. Pinning that depends on
  connection reuse is not pinning.
- **`accept-encoding: identity`.** A decompressor between the socket and the size cap is a place
  for a compressed bomb to expand past it, and `node:http` does not decompress on its own.

## 2. Rejected: patching `globalThis.fetch`, and the undici global dispatcher

Both would cover far more than `web_fetch` — the vendor search providers, any plugin, the model
adapter — and both were rejected for the same reason: **the harness's own model traffic goes
through that function.** A deny arm bricks the agent on its first request. A log arm writes
`x-api-key` and `Authorization` headers into the audit sink, which is the artefact an attacker
reads after the fact. A monkey-patch is also trivially removable by the code it is meant to
govern, and it would fight any other plugin doing the same.

The seam this package registers into is the supported one, and it is the one whose failure modes
the harness already documents.

## 3. Connect-time enforcement is proved by two tests, not one claim

`tests/unit/fetch-provider.spec.ts`:

- **The hook drives the connection.** A request to `pinned.test`, a name with no DNS record
  anywhere, succeeds against a loopback fixture because the injected resolver's answer is what
  the socket followed. If the hook were absent, the system resolver would return NXDOMAIN.
- **A changed answer never reaches the socket.** A resolver returns `203.0.113.7` (public,
  permitted) for the check and the loopback fixture for every call after it. The fixture records
  **zero** requests and the resolver is consulted exactly once. An implementation that
  re-resolved at connect — including one whose `lookup` hook called the resolver again — would
  land on the fixture.

Together those distinguish "pinned to the vetted address" from both "pre-checked then
re-resolved" and "no hook at all". The address-table half is the same seam from the other
direction: a redirect hop whose re-resolution answers `169.254.169.254` is refused with
`blocked-by-private-address` and the second hop is never requested.

The one arm that cannot be reached from the public API is the `socket.remoteAddress` mismatch:
with the lookup hook pinned there is no way to steer the socket elsewhere. It carries a
`v8 ignore` with that reason, and `remoteAddressMismatch` — the decision it makes, including the
`::ffff:` normalisation — is unit-tested on its own.

## 4. Loopback is refused by default, and `allowPrivateAddresses` is how a deployment opens it

harden-runner allowlists RFC1918 by default. For a CI runner in a private VPC that is arguable;
for an agent on a developer's own machine or a build host it is the wrong call, because the
interesting internal targets are exactly the ones on `127.0.0.1` and `10/8`. So the table
refuses everything private and a deployment names what it needs.

That is a rank-2 (deployment) field, never rank 3, and **the cloud metadata endpoints and the
whole link-local range are excluded from it**: an entry overlapping `169.254.0.0/16`,
`168.63.129.16/32` or `fe80::/10` is a load-time error. An agent that can reach
`169.254.169.254` holds the host's cloud role, which is not a trade any deployment should be
able to make by editing one line.

It is also what makes the connect-time tests possible without a network: `127.0.0.1/32` is open
and `127.0.0.2` is not, so a resolver that moves between them is a rebinding a test can observe.

## 5. Two records per hop, and audit mode records Open rather than Refuse

Each hop makes two decisions — the URL against the host policy, then the resolver's answer
against the address table — and each is recorded. The first has no address to report yet; that
is why the spool holds two lines for one successful fetch and why only the second carries
`dst_endpoint.ip`.

In `audit` mode a denied request **completes**. A record claiming `activity_id: 5` (Refuse) for
a connection that was made would be a false negative in the only direction that matters, so the
audit row is `activity_id: 1` (Open), `action_id: 1` (Allowed), `disposition_id: 17` (Logged),
`severity_id: 3`, `is_alert: true`, with `unmapped.dsh.enforced: false`. OCSF's Logged
disposition means exactly this and it is the reason `security_control` is the profile to
declare.

`metadata.profiles` is `['security_control', 'host']` and nothing else. Every OCSF class is
`additionalProperties: false`, so an attribute from an undeclared profile is precisely the
validation failure the declaration exists to prevent — which is also why `ai_agent` is not on
these records even though the sibling forwarder puts it on its own: Network Activity does not
define it.

## 6. The guard mints the identity, and only records when it is the arm that decided

`WebFetchProvider.fetch` receives `{ url }` — no agent, no session, no call id
(`packages/web/web/src/types.ts:113`). `ToolExecution` has the call id but not the turn or step;
those appear beside a `callId` only in the `tool/call` session event. So there are two joins,
both minted here: a `session/event` observer keeps `callId → { turn, step }`, and the guard
notes `url → identity` for the provider to look up moments later. Both maps are bounded and
lossy on purpose — a missed join costs a record its `correlation_uid`, an unbounded map costs
the agent its memory.

Which arm writes the record follows one rule: **the arm closest to the wire owns it.** An
enforced denial in the guard means the provider never runs, so the guard records it; otherwise
the provider records. When `fetch.enabled: false` there is no provider, so the guard records
everything. The same rule for search: the guard owns the record unless a delegate is configured,
in which case the provider does. Without it, every allowed `web_fetch` would be spooled twice.

The guard is registered **unscoped**, on a plain context. Verified in the sibling `dsh-dlp`
work: a global guard applies to every agent, every `run_code` inner sub-call and every subagent
child, while an agent-scoped listener does not see a subagent child's calls, because a child
agent is a sibling of its parent rather than a descendant. A per-agent floor would have a hole
exactly where a prompt-injected agent would spawn a helper.

## 7. The mount check reads two private fields, and says so when it cannot

`ctx.web` exposes no way to enumerate providers or read the configured pin. The check therefore
reads `fetchProviders` / `searchProviders` (the registries) and `fetchProviderId` /
`searchProviderId` (the resolved pin) off the live `WebRuntime`. Both are `private` in TypeScript
and ordinary own properties at runtime; verified against `@deepseek-ai/dsh-web@0.1.0-rc.6`, and
`tests/unit/mount.spec.ts` reads them off a real instance so a rename fails the suite here rather
than silently at a user's install.

`fetchProviderId` is the right field to read rather than `$DSH_WEB_FETCH_PROVIDER`, because the
seam resolves `config.fetchProvider ?? process.env.DSH_WEB_FETCH_PROVIDER` once in its
constructor — the one field already carries the environment override.

Alternatives considered:

- **Probe with a duplicate registration.** Registering a provider under the shipped `http` id and
  catching `WEB_DUPLICATE_PROVIDER` detects that one provider without touching a private field.
  It cannot read the pin, so it produces a false failure for every deployment that pinned this
  package correctly in `cordis.yml`, and it cannot name any provider other than the one id it
  guessed.
- **Do nothing and let the seam fail.** `WEB_PROVIDER_AMBIGUOUS` at the first `web_fetch` names
  neither this plugin nor the fix. CONVENTIONS §2 requires misconfiguration to fail loud at load.

When the fields are unreadable the check does not guess: it fails with "this build does not
expose its provider registry, pin `web.fetchProvider` explicitly" and quotes the patch.

## 8. The search provider wraps a delegate resolved by name, and is unusable without one

The seam gives a search provider nothing to wrap. `ctx.web` has no accessor for registered
providers, and there is no disposer for one this package did not register, so "wrap the provider
the profile already composed" is not expressible.

Two options remained. Importing a vendor package statically would put `@deepseek-ai/dsh-web-*`
into `dependencies`, and a copied dependency closure means two copies of `WebError` and
`HarnessError` in one process — `instanceof` stops working, and the sibling `dsh-dlp` work
already established that a plugin installed under `$DSH_HOME/profiles/<name>/node_modules`
cannot resolve the harness packages from there anyway.

So the delegate is named in configuration and imported at first use, from the running
installation's own module graph. **Without a delegate the provider reports `available(): false`**,
which is the important half: the seam ignores an unusable provider, so mounting this plugin never
displaces a profile's existing search route and never creates the ambiguity the fetch side has to
be configured around.

The outbound-query guard covers the un-delegated composition, and the README says plainly that
result URLs are unfiltered there.

## 9. A closed reason vocabulary, and a `WebError` we do not extend

The reasons are Codex's — `blocked-by-allowlist`, `blocked-by-denylist`,
`blocked-by-private-address`, `blocked-by-scheme`, `blocked-by-credentials`,
`blocked-by-redirect` — so an operator reading two products' logs sees one set of words, and a
model that receives one can act on it instead of retrying a timeout forever.

`NetguardWebError` carries the seam's own `code` values (`WEB_BLOCKED_URL`, `WEB_INVALID_URL`,
`WEB_REDIRECT_BLOCKED`, …) but deliberately does **not** extend `WebError` from
`@deepseek-ai/dsh-web`: that would be a runtime import of a harness package, which §8 explains a
profile-installed plugin cannot rely on resolving. The cost is that the tool registry's
structured `{ name, code }` error metadata — attached only for `HarnessError` instances — is
absent. The denial reason still reaches the model in the message, which is the channel the model
reads.

## 10. `blocked-by-scheme` needs a host to report; a hostless URL does not get it

`gopher://host/`, `ftp://host/` and `ws://host/` are refused as `blocked-by-scheme`, with a
record naming the host they would have reached. `file:///etc/passwd` and `data:text/plain,…`
have no host at all — WHATWG `URL` requires a non-empty host only for special schemes — so there
is no endpoint to put in a `dst_endpoint` and no policy decision to record. Those are reported as
an invalid URL whose message still names the scheme, because that is what the model has to
change.

## 11. The redirect rules are not governed by `mode`

Audit mode relaxes *this package's host policy*. The cross-origin refusal, the hop budget and
the missing-`Location` failure are the shipped `web-fetch-http` provider's own behaviour, which
this provider replaces and preserves. Making them mode-dependent would mean audit mode
introduces a following-redirects behaviour the harness never had, which is a regression dressed
as an observation mode.

## 12. Ranking, and what rank 3 may do

Verbatim from `dsh-dlp`: rank 1 compiled invariants, rank 2 `cordis.yml`, rank 3 a repo-local
`policyFile`. Rank 3 may add deny patterns and raise `audit` to `enforce`. It may not add an
allow, drop back to audit, open an address range, or name the spool. A prompt-injected agent can
write a repo-local file, and there is no legitimate reason for one to widen an egress allowlist.

`enforce: false` is an explicit error rather than an ignored key, so a workspace cannot quietly
half-apply a relaxation. A malformed file invalidates the whole document, is reported on both
`process.stderr` and `ctx.logger`, and is then ignored — aborting `apply()` instead would let a
hostile repository remove the control by committing two broken lines, and would refuse to start
`dsh` in every repository that ships no policy at all.

The harness shares the instinct: `packages/boot/app-boot/src/index.ts:111` forbids a repo-local
`.env` from setting `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY`.

## 13. No public suffix list

`*.co.uk` allows every British company and is easy to write, so a small table of common
second-level suffixes rejects it. A full public suffix list is ~15,000 lines of data that goes
stale and would sit inside the trusted computing base of a security control; a wildcard over a
self-service namespace the table does not know (`*.github.io`, `*.blob.core.windows.net`) is
accepted and documented as the operator's risk. The prefix-wildcard form
(`prod*.blob.core.windows.net`) is rejected outright, because that is the shape that matches
names an attacker can register.

## 14. Coverage: 100% per file, with named exemptions

CONVENTIONS §4 adopts upstream's per-file bar for security code and `vitest.config.ts` enforces
it. Three arms use `/* v8 ignore */` with a stated reason:

- the `socket.remoteAddress` mismatch arm (§3);
- `response.statusCode ?? 0` in two places — a received response always carries a status line;
- the `default` arm of the `RepoPolicyLoad`, `SpoolRead` and `PatternKind` switches, unreachable
  while those unions stay closed, kept so that adding a variant fails the build;
- the process entry at the bottom of `cli.ts`, which `tests/e2e/report.e2e.ts` runs as a real
  subprocess against the built module instead.

Reaching the bar changed the code twice, both times for the better: an unreachable
empty-hostname guard in `identifyHost` came out (WHATWG `URL` refuses an empty host for a
special scheme), and the fleet label/tag lists are now computed once rather than twice.
