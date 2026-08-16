# dsh-netguard

An egress policy for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness): a
host allowlist on harness-originated HTTP, **enforced at connect time**, built as an
out-of-repo plugin.

The harness has no network control of any kind. Its sandbox governs file effects only —
`packages/shell/bash-sandbox/README.md:85` says network and process visibility are outside its
vocabulary — and `web_fetch` is described in-source as an SSRF primitive with private-network
protection "not implemented". This package adds the part that is achievable from an ordinary
mounted plugin.

---

## Read this first: what it does not do

**It is not an egress firewall.** It governs `web_fetch` and `web_search`. It does not see one
byte sent by `bash`, `run_code`, a terminal session, an MCP server, or a delegated external
agent. Governing those needs confinement at the sandbox or network layer, which this package
does not provide.

**It is not a containment boundary.** It runs in-process, at the agent's own uid. `run_code`
executes model-authored TypeScript in a worker thread with `fetch`, `node:net` and
`node:child_process` all reachable — verified by running a faithful reproduction of that
worker's construction; a real TCP connect left the process and `execSync('id -u')` returned the
harness's own uid. So:

- **against a confused or prompt-injected model that asks a tool to fetch a URL, this is a real
  control**;
- **against a model that is deliberately exfiltrating, it is advisory** — that model writes one
  line of `run_code`.

**Four paths stay open with a perfect allowlist.**

1. **The model channel.** The agent encodes a secret into its next prompt and it leaves over
   the one connection the deployment must permit. This is the dominant path and nothing here
   touches it.
2. **Allowlisted destinations.** `github.com` on the allow list is the whole GitHub API as
   whoever `gh` is authenticated as: push to any writable repository, a gist, an issue body.
   It is the widest entry you can add.
3. **`run_code` and `bash`**, which this release does not govern at all.
4. **The browser.** DSH's web UI renders model-authored markdown images from any absolute
   `http(s)` URL, with no CSP anywhere in the repo, and that request is made by *your browser*,
   not by the agent's process.

What it is good for, stated as narrowly as it is true:

- **It prevents accidents.** A build script phoning home, a dependency's postinstall fetching a
  second stage, a `web_fetch` to a hallucinated URL — these stop, and you see them.
- **It raises the cost of an injected agent** that asks a tool to fetch a URL.
- **It answers "which tool call opened this connection"**, because every record carries the
  same `correlation_uid` scheme `dsh-ocsf-forwarder` stamps on its Process Activity records.

---

## Audit mode is the default, and audit mode is not a control

`mode` defaults to `audit`. **In audit mode nothing is denied.** Every decision is recorded and
every request goes through, including the ones the policy would refuse. An installation left in
audit mode has monitoring, not enforcement.

It is the default because enforce-first on a dependency graph nobody can enumerate in advance
gets the control switched off in week one. The value of audit mode is that it writes the allow
list for you:

```sh
dsh-netguard report --suggest     # a ready `allow:` block from the hosts it observed
```

Read that output before using it. It reports what happened, not what should be permitted, and
one line in it may be the request you mounted this plugin to stop. When the list is right, set
`mode: enforce`.

---

## Mounting it: the composition is mandatory

`ctx.web` has **no provider priority and no last-wins rule**. A configured `web.fetchProvider`
(or `$DSH_WEB_FETCH_PROVIDER`) selects one; without a pin, exactly one *usable* provider is
required and two throw `WEB_PROVIDER_AMBIGUOUS` at the first call
(`packages/web/web/src/index.ts:189`). `HttpFetchProvider.available()` returns a hardcoded
`true`, so composing `web-fetch-http` beside this package without a pin breaks `web_fetch`
outright.

`apply()` therefore checks the seam at mount and **fails loud** with the patch you need. It
cannot catch a fetch provider composed *after* this plugin; the shipped bundles compose the web
seam in the base layer and a plugin bundle's rows come after it, so the order that matters in
practice is covered.

Two more facts about the shipped `@deepseek-ai/dsh-base` bundle that decide what you have to
write:

- it mounts **no fetch provider at all**, and `tool-web` ships `fetch: false`, so `web_fetch` is
  not even registered until you turn it on;
- it pins `web.searchProvider: deepseek-official`, so this package's search provider is never
  auto-selected — which is why it reports itself unusable unless you configure a delegate, and
  why mounting this plugin never breaks a profile's existing search route.

```sh
dsh plugin --profile <name> add @deepseek-ai/dsh-headless@0.1.0-rc.6
dsh plugin --profile <name> add dsh-netguard
dsh --profile <name> --dump-config      # the dsh-netguard row should appear
```

Pin `@deepseek-ai/dsh-headless` explicitly: its npm `latest` tag still points at `0.0.1-rc.1`,
so an unpinned install silently resolves to a much older harness.

**Install from the registry or a packed tarball, not from a git spec.**
`dsh plugin add github:CharlotteN7/dsh-netguard` resolves and writes the dependency, but `lib/`
is a build output that git does not carry and no `prepare` script rebuilds it, so the row mounts
and then fails to load. To install from a checkout, build first and add the tarball:

```sh
git clone https://github.com/CharlotteN7/dsh-netguard && cd dsh-netguard
pnpm install && pnpm run build && pnpm pack
dsh plugin --profile <name> add ./dsh-netguard-0.1.0.tgz
```

Then write the composition into the profile's `cordis.patch.yml`. **A patch REPLACES a row's
whole `config`**, so every key the row needs is restated:

```yaml
# $DSH_HOME/profiles/<name>/cordis.patch.yml
- id: web
  config:
    fetchProvider: dsh-netguard
    searchProvider: deepseek-official   # whatever your profile already uses

- id: tool-web
  config:
    fetch: true                          # the base bundle ships this off
    searchTimeoutMs: 60000

# Only if your composition mounts the shipped provider; the base bundle does not.
- remove: [web-fetch-http]

- id: dsh-netguard
  config:
    mode: audit
    allow: []
    deny: []
    spoolPath: /var/log/dsh/netguard.ocsf.jsonl
```

If you get this wrong, the mount fails with a message naming the conflicting provider and
quoting the patch above. It does not start half-working.

---

## Configuration

```yaml
- id: dsh-netguard
  name: 'dsh-netguard'
  config:
    mode: audit                          # or enforce
    allow: ['**.github.com', '*.example.com', 'registry.npmjs.org:443']
    deny: ['*.internal.example']
    allowPrivateAddresses: []            # CIDR blocks; see below
    policyFile: ./.dsh-netguard.yml      # optional, lowest trust
    spoolPath: /var/log/dsh/netguard.ocsf.jsonl
    fetch:
      enabled: true
      timeoutMs: 30000
      maxRedirects: 5
      maxResponseBytes: 5000000
      maxBodyChars: 100000
      maxUrlLength: 2048
      userAgent: 'dsh-netguard/0.1.0 (+https://github.com/CharlotteN7/dsh-netguard)'
    search:
      enabled: true
      delegate:                          # absent = the search provider stays unusable
        module: '@deepseek-ai/dsh-web-search-exa'
        export: 'ExaSearchProvider'
        options: { apiKey: '...', baseURL: 'https://api.exa.ai', searchType: auto, highlightsPerResult: 1 }
    hmacKey: { source: ephemeral }       # or { source: env, variable: NETGUARD_KEY }
    fleet: { tenantUid: acme, labels: [prod] }
```

### The pattern grammar

Codex's semantics, which are the only unambiguous ones in the prior art:

| Pattern | Matches |
|---|---|
| `example.com` | that host, and nothing else |
| `*.example.com` | subdomains only — **never** the apex |
| `**.example.com` | the apex **and** every subdomain |
| `*` | everything; accepted in `allow` only |
| `example.com:8443` | that host on that port only |
| `[::1]`, `[::1]:443` | an IPv6 literal, always bracketed |

**A deny match wins over every allow match**, across every configuration source. **An empty
allow list denies everything**, and that is what ships.

A pattern that could be read two ways is refused at load rather than widened. Refused:
a prefix wildcard (`prod*.blob.core.windows.net` — that namespace is self-service, so the
pattern matches names an attacker can register), a wildcard inside a label, a wildcard over a
top-level domain (`*.com`), a wildcard over a common public suffix (`*.co.uk`), an unbracketed
IPv6 literal, a URL, a path, or credentials.

The public-suffix check is an **approximation** and is one on purpose: shipping a full public
suffix list would put a 15,000-line data file that goes stale into the trusted computing base of
a security control. It rejects the spellings that are both easy to write and catastrophic. A
wildcard over a self-service namespace it does not know — `*.github.io`,
`*.blob.core.windows.net` — is accepted, and is your risk.

Hosts are compared canonically on both sides. `2130706433`, `0x7f000001`, `127.1` and
`017700000001` are all `127.0.0.1` because the hostname is read from `url.hostname` and WHATWG
`URL` has already normalised them; `[::ffff:127.0.0.1]`, the `[::ffff:7f00:1]` spelling `URL`
leaves behind, the deprecated `[::127.0.0.1]` form and the NAT64 prefix `[64:ff9b::7f00:1]` are
all unwrapped to `127.0.0.1` by this package. A name is IDNA-normalised and a trailing dot is
dropped.

### Addresses that are never reachable

Every resolved address is checked against a fixed table before the socket opens, and **one
refused address refuses the whole answer** — a name with a public `A` record and an internal
`AAAA` record reaches the internal host on any client that prefers IPv6, and picking the "good"
one would make the outcome depend on address selection order rather than on policy.

Refused: `0.0.0.0/8`, `10/8`, `100.64/10`, `127/8`, `169.254/16`, `172.16/12`, `192.0.0/24`,
`192.168/16`, `198.18/15`, `224/4`, `240/4`, `::/128`, `::1/128`, `fc00::/7`, `fe80::/10`,
`ff00::/8`, and the cloud metadata endpoints `169.254.169.254`, `169.254.170.2`,
`168.63.129.16`, `fd00:ec2::254`.

`allowPrivateAddresses` opens named blocks for a deployment that genuinely needs an internal
service — `['10.0.0.0/8']` for a corporate wiki, `['127.0.0.1/32']` for a local fixture.
harden-runner allowlists RFC1918 by default; for an agent on a developer's own machine or a
build host that is the wrong call, so nothing is reachable here unless you name it. **The cloud
metadata endpoints and the whole link-local range cannot be opened at all**: an entry that
overlaps them is a load-time error, because an agent that can reach `169.254.169.254` holds the
host's cloud role.

### Configuration trust ranking

| Rank | Source | May |
|---|---|---|
| 1 | invariants compiled into the package | everything; not configurable |
| 2 | `cordis.yml` / bundle patch config | set every field |
| 3 | `policyFile` — a repo-local YAML file | **tighten only** |

Rank 3 is attacker-controlled: a hostile repository ships one, and a prompt-injected agent can
write one. It may add deny patterns and raise `audit` to `enforce`. That is all:

```yaml
v: 1
addDeny: ['*.internal.example', 'paste.example']
enforce: true
```

There is no `allow`, no way to open an address range, no way to name the spool, and
`enforce: false` is an error rather than an ignored key. Any other key, and any downgrade, makes
the **whole file invalid**: it is reported on `process.stderr` and the deployment's logger, then
ignored, never obeyed in part. A missing file is not an error — the recommended `policyFile` is
workspace-relative, so failing the mount would stop `dsh` from starting in every repository
without one, and would let a hostile repository remove the control by shipping a broken file.

The file is parsed with `js-yaml` under `JSON_SCHEMA`, so a `!!js/function` tag is a parse error
rather than code execution, and it never goes near the Cordis loader.

The harness takes the same line: `packages/boot/app-boot/src/index.ts:111` forbids a repo-local
`.env` from setting `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY`.

---

## What enforcement actually means

### The fetch provider: connect time, not parse time

The guarded provider is built on `node:https` / `node:http` rather than global `fetch`, for one
reason: **global `fetch` ignores a `lookup` function in its `RequestInit`.** Without that hook,
the check and the connect are two separate name resolutions, and a name that answers with a
public address for the check and a loopback address a millisecond later is the whole
DNS-rebinding attack. A pre-check cannot close it.

So, per hop:

1. Parse with WHATWG `URL` and read `url.hostname`, never the raw string.
2. Refuse a non-`http(s)` scheme and any embedded credentials.
3. Resolve the name **once**, and check every address the resolver returned.
4. Pass a `lookup` hook that returns **only the vetted address**, so the socket cannot be
   pointed anywhere else between the check and the connect, and verify `socket.remoteAddress`
   once the socket is up.
5. Follow redirects here, one hop at a time, re-running the whole check per hop, and keep the
   shipped provider's **cross-origin refusal** so an allowlisted host cannot be used as an open
   redirector into one that is not.

`agent: false` is deliberate: a pooled agent may hand back a socket opened earlier for the same
hostname, to whatever address that earlier resolution produced, which would make the pinning
depend on connection reuse. `accept-encoding: identity` is deliberate too: a decompressor
between the socket and the size cap is a place for a compressed bomb to expand past it.

`tests/unit/fetch-provider.spec.ts` proves the pinning with two tests rather than one claim: a
request to a host with no DNS record anywhere succeeds because the lookup hook is what drives
the connection, and a resolver that answers `203.0.113.7` first and the loopback fixture
afterwards never reaches the fixture — the socket goes to the checked address and the fixture
records zero requests.

The redirect rules are **not** governed by `mode`. They are the shipped provider's own
behaviour, which this one replaces and preserves; audit mode relaxes this package's *host
policy*, not the seam's pre-existing transport hygiene.

### The tool guard

`ctx.tools.guard()` is registered **unscoped**, on a plain context, so it applies to every
agent, every `run_code` inner sub-call and every subagent child — an agent-scoped guard would
miss exactly the child a prompt-injected agent would spawn. It runs after the whole
`tools/pre-execute` waterfall, so it reads what every listener finally left behind.

It does two things: it refuses a `web_fetch` or `web_search` the policy denies (in `enforce`
mode), and it mints the tool-call identity a provider never receives — `WebFetchProvider.fetch`
is handed `{ url }` and nothing else, with no agent, session or call id.

### The search arms

The query is a real exfiltration sink: the query string *is* the payload, and it reaches the
vendor before any result comes back. What this package filters is the hosts named inside it, so
`site:attacker.example <secret>` does not go out. **A plain-text secret in a plain-text query
still reaches the vendor**, and no host policy changes that.

The vendor's transport is not ours to govern — every shipped provider calls bare global `fetch`
against its own configured `baseURL`. What is governed is the result: a source whose host the
policy denies is dropped before the model sees it.

The guarded search provider wraps a vendor provider named in `search.delegate`, imported at
first use. **Without a delegate it reports itself unusable**, so the profile's own search route
keeps working and only the outbound-query guard applies.

### Denial reasons

A closed vocabulary, borrowed from Codex, so the model gets something it can act on rather than
a timeout:

`blocked-by-allowlist` · `blocked-by-denylist` · `blocked-by-private-address` ·
`blocked-by-scheme` · `blocked-by-credentials` · `blocked-by-redirect`

```
dsh-netguard refused this request to paste.example: blocked-by-allowlist. Ask the user to add
the host to netguard's allow list if this request is expected.
```

---

## Where to start an allow list

It ships **empty**, which under `mode: enforce` denies everything. A guessed default is
simultaneously too wide and too narrow, and audit mode exists to derive the real one. What a
typical starting set costs:

| Entry | Needed for | What it also permits |
|---|---|---|
| the resolved LLM `baseURL` host | the agent loop and `web_search` | the model channel — see the limits above |
| `registry.npmjs.org` | installs | `npm publish` to an attacker-owned package |
| `github.com`, `codeload.github.com`, `**.githubusercontent.com` | `git`, `gh` | push to any writable repository, a gist, an issue body — the widest entry |
| `pypi.org`, `files.pythonhosted.org` | `pip` | the same publish channel |

Derive the LLM host from your resolved configuration rather than hardcoding it, or self-hosted
and gateway deployments break. That entry buys nothing here directly — this package does not
govern the model channel, which is the harness's own adapter calling global `fetch` — so it
matters only to a network-layer control that consumes the same list.

---

## What it records

One OCSF **Network Activity (4001)** record per decision, one JSON object per line in
`spoolPath`, with the `security_control` profile declared.

| Outcome | `activity_id` | `action_id` | `disposition_id` | `severity_id` |
|---|---|---|---|---|
| allowed | 1 Open | 1 Allowed | 1 Allowed | 1 Informational |
| denied, `mode: enforce` | 5 Refuse | 2 Denied | 2 Blocked | 3 Medium |
| denied, `mode: audit` | 1 Open | 1 Allowed | 17 Logged | 3 Medium |

The audit row is worth saying out loud: in audit mode the connection **was made**, so the record
says Open and Allowed. `disposition_id: 17` (Logged) and `unmapped.dsh.enforced: false` are what
tell a SOC that the policy would have refused it. A record claiming Refuse for a request that
completed would be a false negative in the only direction that matters.

A first-seen host for this installation, and any denial audit mode let through, set
`is_alert: true`.

**Nothing is ever appended to the session log.** `Session.append()` offers no way to set the
envelope's `ignorable` flag, so an out-of-repo event type is written without it and the user's
next resume throws `SessionFormatUnsupportedError` and refuses the whole session. This package
is read-side with respect to the log, and an E2E assertion checks that no row in it carries one
of our types.

Each record therefore carries its own identity, using `dsh-ocsf-forwarder`'s scheme unchanged:
`metadata.uid = <session>:<seq>` and `metadata.correlation_uid = <session>:<callId>`. That last
one is the reason to run the two packages together: the forwarder already emits Process Activity
1007 for every tool call, so the same key on a 4001 record answers *which tool call opened this
connection* — at tool-call granularity, which no other harness can do.

### The privacy lane

Verbatim: hostname, port, resolved IP address, verdict, matched rule id, tool name.
Digested: the full URL, and any search query, as `HMAC-SHA256(key, value)` truncated to 128
bits, with the length beside it. The digest is stable, so a SIEM can still join on it; nobody
reading the spool learns the value. This mirrors `dsh-ocsf-forwarder`'s lane rule exactly, so
records from both packages can sit in one index without one of them being the leak.

```json
{
  "class_uid": 4001, "category_uid": 4, "type_uid": 400105,
  "activity_id": 5, "action_id": 2, "disposition_id": 2, "severity_id": 3,
  "is_alert": false, "time": 1755300000000,
  "message": "netguard refused paste.example: blocked-by-allowlist",
  "metadata": {
    "product": { "name": "dsh-netguard", "vendor_name": "dsh-security-plugins", "version": "0.1.0" },
    "version": "1.9.0", "profiles": ["security_control", "host"],
    "log_provider": "deepseek-harness", "log_name": "netguard",
    "uid": "session-88:4", "correlation_uid": "session-88:call-2", "sequence": 4
  },
  "dst_endpoint": { "hostname": "paste.example", "port": 443, "svc_name": "https" },
  "connection_info": { "direction_id": 2, "protocol_name": "tcp" },
  "firewall_rule": { "uid": "deny:paste.example", "name": "blocked-by-denylist" },
  "unmapped": { "dsh": {
    "v": 1, "kind": "fetch", "mode": "enforce", "verdict": "denied", "enforced": true,
    "reason": "blocked-by-allowlist", "tool": "web_fetch", "session_id": "session-88",
    "call_id": "call-2", "turn": 1, "step": 0, "first_seen_host": true,
    "url_digest": "hmac-sha256:9f2a…", "url_length": 63, "has_query": true, "hop": 0
  } }
}
```

A spool write failure is reported on `process.stderr` **and** `ctx.logger`, then swallowed: the
spool is evidence, not enforcement, and letting a full disk turn every request into a refusal
would trade an egress control for an availability outage. Both channels are used because
`ctx.logger`'s default exporter is an in-memory ring buffer that no shipped bundle drains, so a
message sent only there is invisible on a stock install.

---

## Reading it back

```sh
dsh-netguard report                       # everything in $DSH_HOME/netguard/decisions.ocsf.jsonl
dsh-netguard report --since 24h           # or an ISO timestamp
dsh-netguard report --session <id>
dsh-netguard report --suggest             # a ready allow: block from the observed hosts
dsh-netguard report --spool /var/log/dsh/netguard.ocsf.jsonl
```

It imports nothing from the harness, so it runs wherever the package is installed, with no
profile and no `dsh` on the path. A plugin installed into a profile puts its bin in that
profile's `node_modules/.bin`, which is not on `PATH`:

```sh
"$DSH_HOME/profiles/<name>/node_modules/.bin/dsh-netguard" report
```

The spool is append-only and a run can be interrupted mid-append, so a line that does not parse
as a record is counted and reported rather than trusted.

---

## Known limitations

- **`bash`, `run_code`, terminals, MCP servers and delegated agents are not governed.** Not a
  gap to be closed at this layer; it needs the sandbox.
- **The model channel is not governed**, and it is the dominant exfiltration path.
- **The spool is not rotated.** This package writes one record per decision — a few lines per
  session, not one per session event — so the file grows slowly. Point `logrotate` at it on a
  long-lived installation.
- **No public suffix list.** The wildcard check is a documented approximation; see the grammar
  section.
- **A query with no host in it is not filtered.** A host allowlist has nothing to decide there.
- **Without a `search.delegate`, result URLs are not filtered** — only the outbound query is
  checked, because the vendor provider the seam selected answers the seam directly and never
  passes through this package.
- **A fetch provider composed *after* this plugin is not detected at mount.** It surfaces as
  `WEB_PROVIDER_AMBIGUOUS` at the first `web_fetch` instead.
- **The mount check reads two private fields** of the live `WebRuntime` (`fetchProviders` and
  `fetchProviderId`). That is a deliberate coupling to a harness version; when a rename makes
  them unreadable, the check says it could not verify the composition and tells you to pin the
  provider explicitly rather than inventing a verdict. See [ADR.md](ADR.md).
- **`globalThis.fetch` is not patched and the undici global dispatcher is not touched.** Both
  were considered and rejected: the harness's own model traffic goes through the same function,
  so a deny arm bricks the agent and a log arm writes `x-api-key` and `Authorization` headers
  into the sink.

---

## Development

```sh
nvm use 22           # Node ^22.19.0 || >=24, and pnpm 11
pnpm install
pnpm run typecheck
pnpm run test        # unit
pnpm run test:coverage
pnpm run test:e2e    # boots a real dsh against a mock model; no API key
```

Coverage is gated at 100% per file. This is a security control, so an arm nothing exercises is
an arm nobody has checked; the few genuinely unreachable lines carry a `v8 ignore` with a stated
reason, and each of those has its decision function unit-tested on its own.

The E2E harness boots a `dsh` checkout beside this one (`../dsh`); point `DSH_REPO` elsewhere to
override. That checkout needs `pnpm run build:lib:host` to have run at least once. Set `DSH_CLI`
to an installed `node_modules/@deepseek-ai/dsh/lib/bin.js` to run against the published CLI
instead, which needs no monorepo — that is what CI does.
