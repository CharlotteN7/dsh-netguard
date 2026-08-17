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

Which arm writes the record for a *policy decision* follows one rule: **the arm closest to the
wire owns it.** An enforced denial in the guard means the provider never runs, so the guard
records it; otherwise the provider records. When `fetch.enabled: false` there is no provider, so
the guard records every policy decision. The same rule for search: the guard owns the record
unless a delegate is configured, in which case the provider does. Without the rule, every
allowed `web_fetch` would be spooled twice.

One class of decision is outside that rule and always belongs to the guard: a call it cannot
turn into a target at all. A `url` argument that is not a string, and text that is not a URL,
never reach a provider that could record them, and the provider's own refusal is a thrown error
rather than a record. The guard therefore writes those itself, against a marker in place of a
hostname — otherwise a request that named no host we could decide would be invisible to the
audit lane, which is the one lane that is supposed to be total. A call carrying no `url` or
`query` key at all is the exception: it names no target and opens no socket.

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
be configured around. The one composition that has to fail loud is a profile that *pins*
`web.searchProvider: dsh-netguard` without configuring a delegate: the seam then selects a
provider that answers nothing, so the mount check refuses it rather than letting every
`web_search` fail at call time.

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

## 10. `blocked-by-scheme` needs a host to report; a hostless URL gets a marker

`gopher://host/`, `ftp://host/` and `ws://host/` are refused as `blocked-by-scheme`, with a
record naming the host they would have reached. `file:///etc/passwd` and `data:text/plain,…`
have no host at all — WHATWG `URL` requires a non-empty host only for special schemes — so there
is no endpoint to put in a `dst_endpoint`. The message the model receives still names the
scheme, because that is what it has to change, and the record is written against the
`(unparsed-url)` marker with a digest of the argument: a decision with no endpoint is still a
decision, and dropping it would put a hole in the one lane that is supposed to be total.

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

What the bar does not catch is a vacuous assertion. `plugin.spec.ts` called the floor as
`plugin.guards[0]?.(…)`, which is `undefined` when the mount registered no guard, so every test
asserting that the guard abstains passed against no guard at all — 100% coverage throughout, since
`apply` still ran. The mount helper now binds the guard through an accessor that throws when none
was registered. Verified by removing the registration from `apply`: three of those tests passed
before the change and fail after it.

## 15. Length is a policy decision, and it is governed by `mode`

`fetch.maxUrlLength` and `search.maxQueryLength` bound work this package does synchronously
inside `ctx.tools.guard()`, so both have to exist. What they are *not* is a parse failure. An
over-length URL still names a host, so it is parsed, decided against the host policy, and denied
with that host's verdict — or with `blocked-by-url-length` when the allow list covers the host.
Treating it as unparseable is what let a padded URL reach a denied host with nothing spooled.

Both are therefore ordinary denials and audit mode relaxes them, exactly as it relaxes an
allowlist denial: audit mode's contract is that every decision is recorded and no request is
refused, and a limit that still refused in audit mode would be a second, undocumented mode. The
transport hygiene that audit mode does *not* relax is the redirect rules (§11), which are the
shipped provider's own behaviour rather than this package's policy.

An over-length query is the one asymmetry, and it is fail-closed by construction: the hosts in
it are never enumerated, so `checkQuery` cannot say the query is clean. It reports a denial
against the `(query)` marker, which audit mode records and permits like any other.

## 16. A bare host in prose is a heuristic, and it is deliberately conservative

The outbound-query filter reads hosts out of model-authored text. Three spellings are read as
destinations: a full URL, a `site:` / `inurl:` / `link:` argument, and a bare dotted token. Only
the third is ambiguous, and it is ambiguous in the direction that hurts: `index.js`,
`readme.md`, `setup.py`, `asp.net` and `file.tar.gz` are filenames in ordinary developer
questions, and evaluating them against an egress allowlist refuses the work rather than the
attack. Measured on eleven realistic queries, the earlier "any dotted token ending in two or
more letters" rule refused nine.

So a bare token needs a top-level label that is both delegated and not a common source-file or
archive extension. That list is an approximation of the root zone for the same reason §13 keeps
no public suffix list, and it is only ever consulted for the bare form: the spellings an
exfiltration query actually uses are unaffected by it.

A bare match is also never treated as a sighting. It does not enter the host memory and it does
not appear in `report --suggest`, because a word inside a question is not a connection anything
made, and an allow list derived from words is worse than no allow list.

## 17. The verbatim lane validates, and `report --suggest` validates again

`dst_endpoint.hostname`, `observables[].value` and `message` are verbatim fields. Two sources
can put a string there that is not a hostname: a vendor search result, whose `url` is whatever
the vendor sent, and WHATWG `URL` itself, which keeps `'`, `"`, a backtick, `$`, `;`, `,` and
`{` inside a hostname. `report --suggest` renders those fields into single-quoted YAML that the
README tells operators to paste into `cordis.yml`, and a quote inside a hostname closes the
quoting.

The rule is one line, applied at the single place a host reaches a record: a plain host spelling
or a fixed marker, with the original value carried as a keyed digest in the extension
attributes. `report --suggest` then applies its own `[a-z0-9._-]+` test on the way out, because
the spool is a durable boundary this package reads back — written by other versions, appended
to under crash — and a reader that trusts what it parsed is the same defect one layer down.

## 18. `metadata.uid` is namespaced here, and left alone in `dsh-ocsf-forwarder`

Both packages emitted `<session>:<seq>` as `metadata.uid`. The two `seq` values count different
things — this package's is a per-process decision counter, the forwarder's is the session log's own
event sequence — and both start near 1 in the same session. So `session-88:4` was the identity of
two unrelated records, one Network Activity and one Process Activity.

That is exactly the composition both READMEs sell. The forwarder's says to deduplicate on
`metadata.uid`; this one says records from both packages can sit in one index. Follow both and the
SIEM silently drops netguard records as duplicates of forwarder records — an audit lane losing
evidence with nothing anywhere reporting it.

This package's key is now `<session>:netguard:<seq>`. The forwarder's is unchanged, and the
asymmetry is the decision, not an oversight: it is the older, published emitter, and changing its
key would break deduplication for everyone already ingesting it, including on records already in an
index. This package is `0.1.0` with no consumers, so it is the one that can afford to move. Anyone
later "tidying" the two into one scheme would recreate the collision.

`metadata.correlation_uid` stays `<session>:<callId>` in both, because there the *point* is that the
two packages produce the same value: it is what joins a connection to the tool call that opened it.
A shared join key and a shared idempotency key are opposite requirements.

## 19. The install uid lives under the harness home, shared with the other producers

`device.uid` is documented as the stable install identity of a machine. Both this package and
`dsh-ocsf-forwarder` defaulted it to `<spoolPath>.install-uid`, and the two spool paths differ by
design, so one host minted two uids and its two OCSF producers disagreed about which device they
were describing. Anything grouping by `device.uid` saw two machines.

Both packages now default to `$DSH_HOME/install-uid`, resolved the way the harness resolves its
home — `$DSH_HOME` when set to something other than whitespace, otherwise `~/.dsh`. Only the default
moved: `fleet.installUidPath` still overrides it, still has to be absolute, and an explicit
`fleet.installUid` still skips the file entirely.

A uid an earlier release left beside the spool is read on first run and written through, because an
upgrade that re-identifies the host destroys exactly the continuity the sidecar exists to provide.
On a host where both packages carry a legacy uid the first to mount seeds the shared file and the
other adopts it; never migrating would leave the two producers permanently disagreeing, which is the
defect being fixed.

Persisting stays best effort, unchanged: a home this process cannot write is reported and the
records carry a per-process uid. The forwarder's copy of this helper threw instead, which failed the
whole mount over an unwritable sidecar; it now behaves as this one does.

## 20. The harness peers are caret ranges; `@deepseek-ai/cordis` stays exact

Every `@deepseek-ai/dsh-*` peer was pinned to the exact version `0.1.0-rc.6`. That made
`npm install dsh-netguard` fail outright the moment upstream published `0.1.0-rc.7`:
`@deepseek-ai/dsh-tools@0.1.0-rc.6` declares `@deepseek-ai/dsh-system-prompt@^0.1.0-rc.6`, which now
resolves to rc.7, which requires `@deepseek-ai/dsh-llm@^0.1.0-rc.7` — a version the exact pin
excludes, so `npm` refuses the whole tree with `ERESOLVE`. `pnpm` still resolved it, so
`dsh plugin add` and CI kept passing while every `npm` user was broken.

The peers are `^0.1.0-rc.6`, which is the range shape upstream uses between its own packages, so the
tree `npm` builds around this plugin is the one the harness builds for itself. The end-to-end job
runs against every published rc the range admits rather than one pinned version, so the next rc
fails a named CI leg instead of a user's install.

`@deepseek-ai/cordis` stays at exactly `4.0.1`. It is not part of the rc train — `4.0.1` is the only
release upstream's own `^4.0.1` ranges resolve to, so the exact pin excludes nothing that exists —
and it is the object model the harness and every plugin share, where a second copy in the tree does
not compose.

## 21. Distinct-URL cardinality is a signal, because the channel it sees is invisible to an allowlist

CVE-2026-54316 is classified CWE-515, a covert storage channel, and it is the case a host
allowlist cannot decide **by construction**: `huggingface.co` is allowlisted as a bare hostname,
and the exfiltration is carried by *which* of many URLs on that one allowed host is requested,
read back out of the vendor's own download counters. No response body is needed, no denied host is
ever contacted, and every individual request is exactly what the policy permits. Nothing in the
allow/deny evaluation can separate that traffic from ordinary use, because there is nothing about
any one request to separate.

What separates it is the count. Every full URL is already reduced to an HMAC digest for the
record, so the distinct-URL count per `(session, host)` is available without storing or logging
one URL: the counter holds digests. It goes into each record as `distinct_urls` and raises
`is_alert` past `alerts.distinctUrlsPerHost`, in exactly the place `first_seen_host` already
raises it.

**It is a signal and not a block, deliberately.** A refusal at 32 URLs would refuse a repository
walk, a documentation crawl and a package index sweep, all of which are the work; the threshold
that stops the channel and the threshold that stops the job are the same number. The default of
32 is a judgement rather than a measurement: past what one session's reading produces, inside
what a channel carrying a short secret needs (one request per byte puts a 32-byte token at 32
requests). It is a rank-2 deployment field for that reason, and `0` keeps the count and drops the
alert.

Three narrower choices inside it:

- **Only hop 0 is counted.** A redirect target is the server's choice, not the agent's, so
  counting redirect hops would let a redirecting host raise the alert on everyone who visits it.
- **The count is per session, not per installation.** The claim is about one agent's behaviour in
  one run; an installation-lifetime count would alert on every long-lived install eventually.
  A record whose tool-call join missed has no session id, and those share one pair per host —
  which can only over-count, never under-count.
- **The state is capped like the join maps** (§6): 64 `(session, host)` pairs, 256 digests each,
  least-recently-counted pair evicted, count saturating at the cap. Same reason as there — a
  missed count costs a signal, an unbounded map costs the agent its memory.

The honest limit is in `docs/limitations.md`: a patient exfiltrator who stays under the threshold,
or spreads the channel across sessions or across several allowed hosts, never trips it. It raises
the cost of the channel and leaves evidence in the lane an operator reads; it does not close it.

## 22. Path-scoped allow entries, and the six refusals that make them unambiguous

`hosts.ts` used to refuse any pattern containing a path, and that was the right default: a
half-supported path syntax in a security control is worse than none. CVE-2026-54316 is the
argument for revisiting it. `huggingface.co` allowlisted as a bare hostname is the widest grant
the grammar could express for that host, and `huggingface.co/<org>/<repo>` is a real narrowing —
the same complaint the README makes about `github.com` being the widest entry you can add.

So an **allow** entry may carry a path. The grant is the path itself and everything under it,
ending on a segment boundary (`/api` covers `/api/v2`, never `/apiv2`), matched case-sensitively
because only a URL's scheme and host are case-insensitive.

The design is in what it refuses. Each of these is a spelling an operator and this package could
read differently, and the grammar's rule is that such a pattern fails at load:

1. **A path on a deny entry.** A deny is host-wide; a path would make it refuse *less* than the
   same line without one, which is the single most dangerous direction to be misread in. It also
   keeps the rank-3 repo-local tier (§12) path-free for free, since that tier can only add denies.
2. **A trailing slash**, and a path that is only `/`. One grant needs one spelling; `/api/` and
   `/api` would otherwise be two ways to write the same thing, and `example.com/` would be a
   "narrowing" that narrows nothing.
3. **A wildcard inside the path.** A path grant is already a prefix, so `example.com/org/*` is
   the entry without the wildcard, and `example.com/org/re*o` is the prefix-wildcard shape §13
   refuses for hosts.
4. **A query string or a fragment.** Matching is on the path alone. A pattern carrying `?token=`
   would look like a constraint this package does not apply, which is worse than not accepting it.
5. **A `.` or `..` segment.** WHATWG `URL` resolves those away before the decision, so such a
   pattern would match nothing — silent in an allow list, exactly the failure mode the interior
   wildcard refusal exists for.
6. **A path on an IP address.** `10.0.0.0/8` is a CIDR block, and CIDR blocks are what an
   operator writes in `allowPrivateAddresses` one field above. Reading it as host-plus-path would
   compile a different policy from the one that was written.

Three properties outside the grammar carry the rest of the weight:

- **Per hop.** The fetch provider re-runs `checkUrl` for every redirect target, so the path is
  re-decided on each hop and a granted path cannot be an open redirector into one that is not.
  That needed no new code — only the path reaching `evaluate` — and `fetch-provider.spec.ts`
  proves it with a *same-origin* 302 out of the grant, which the existing cross-origin refusal
  does not catch.
- **A percent-encoded slash matches nothing.** `URL` leaves `%2f` alone, and origin servers
  disagree about whether it ends a segment. Rather than pick a reading, a request path carrying
  one matches no path-scoped rule at all — fail closed, and the request is refused as an
  allowlist denial.
- **The privacy lane does not move.** A request path is attacker-influenced text and never
  reaches a verbatim field: not `dst_endpoint.hostname`, not `observables[].value`, not
  `message`, which still names the host and the reason only. The one place a path appears is
  `firewall_rule.uid`, as part of the matched pattern's own source text — deployment
  configuration, rank 2, not request text. `report --suggest` needs no change for the same
  reason: it derives its lines from the recorded *hosts*, so no path can reach the YAML an
  operator pastes into `cordis.yml`.

Two behaviours are deliberate rather than incidental. A request to an allowed host outside its
granted path is `blocked-by-allowlist` — no new reason word was added to a vocabulary shared with
another product, and the advice that reason carries ("ask for the entry you need") is the right
advice here. And a **search query naming the host is not refused**: that filter reads hosts out
of prose, where there is no path to decide, and refusing every mention of a host the policy
allows at one path would refuse the work rather than the attack (§16 makes the same trade). A
result URL from a search is decided against the path in full, because the model can hand one
straight to `web_fetch`.
