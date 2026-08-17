# dsh-netguard

An egress policy for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness): a host
allowlist on the `web_fetch` and `web_search` tools, checked at connect time, built as an
out-of-repo plugin.

The harness has no network control of any kind — its sandbox governs file effects only, and
`web_fetch` is described in-source as an SSRF primitive with private-network protection "not
implemented". This package adds the part that is achievable from an ordinary mounted plugin.

📖 **[Full documentation](https://charlotten7.github.io/dsh-netguard/)**

## Three things to know before you install it

**It ships in `audit` mode, where nothing is refused.** Every decision is recorded and every
request goes through, including the ones the policy would deny. `mode: enforce` is what turns
records into refusals. Audit-first is deliberate — enforce-first on a dependency graph nobody can
enumerate gets the control switched off in week one — but an installation left in audit mode has
monitoring, not enforcement.

**It is not an egress firewall.** It governs those two tools and nothing else. It does not see one
byte sent by `bash`, `run_code`, a terminal, an MCP server, or a delegated agent. A build script
phoning home does not stop, and neither does a dependency's postinstall fetching a second stage.

**It is not a containment boundary.** It runs in-process at the agent's own uid. Against a
confused or prompt-injected model that asks a tool to fetch a URL, it is a real control. Against a
model that is deliberately exfiltrating, it is advisory — that model writes one line of
`run_code`. The model channel itself is the dominant exfiltration path and nothing here touches
it.

[What it does not do, in full →](https://charlotten7.github.io/dsh-netguard/)

## Install

```sh
dsh plugin --profile <name> add @deepseek-ai/dsh-headless@0.1.0-rc.6
dsh plugin --profile <name> add dsh-netguard
dsh --profile <name> --dump-config      # the dsh-netguard row should appear
```

**The composition is mandatory.** `ctx.web` has no provider priority and no last-wins rule, so
mounting this beside another fetch provider breaks `web_fetch` outright with
`WEB_PROVIDER_AMBIGUOUS`. Write this into the profile's `cordis.patch.yml` — a patch replaces a
row's whole `config`, so every key is restated:

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

- id: dsh-netguard
  config:
    mode: audit
    allow: []
    spoolPath: /var/log/dsh/netguard.ocsf.jsonl
```

Get it wrong and the mount fails loud, naming the conflicting provider and quoting the patch you
need. Install from the registry or a packed tarball, **not** from a git spec — `lib/` is a build
output git does not carry.

[Install and composition in full →](https://charlotten7.github.io/dsh-netguard/install.html)

## Configure

Every path must be absolute; a relative one resolves against the workspace, which is the directory
the agent being recorded can rewrite. An empty allow list denies everything, and a deny match wins
over every allow match.

```yaml
- id: dsh-netguard
  config:
    mode: audit                          # or enforce
    allow: ['**.github.com', 'registry.npmjs.org:443']
    deny: ['*.internal.example']
    spoolPath: /var/log/dsh/netguard.ocsf.jsonl
```

Pattern grammar is Codex's: `*.example.com` is subdomains only, `**.example.com` includes the
apex. A pattern that could be read two ways is refused at load rather than widened.

[Configuration reference →](https://charlotten7.github.io/dsh-netguard/configuration.html) ·
[What enforcement means →](https://charlotten7.github.io/dsh-netguard/enforcement.html)

## What it records

One OCSF **Network Activity (4001)** record per decision, one JSON object per line, with the
`security_control` profile declared. Verbatim: a validated hostname, port, resolved address,
verdict, matched rule. Digested as HMAC-SHA256: the full URL, any search query, and any string
that was supposed to be a hostname and is not.

Records carry the same `correlation_uid` scheme `dsh-ocsf-forwarder` stamps on its Process
Activity records, so the two together answer *which tool call opened this connection*. Nothing is
ever appended to the session log.

[Record format and the privacy lane →](https://charlotten7.github.io/dsh-netguard/records.html)

## Reading it back

```sh
dsh-netguard report                  # everything in the spool
dsh-netguard report --since 24h
dsh-netguard report --suggest        # a ready allow: block from the hosts it observed
```

Read `--suggest` output before using it. It reports what happened, not what should be permitted,
and one line in it may be the request you mounted this plugin to stop.

The CLI imports nothing from the harness, so it runs wherever the package is installed. A plugin
installed into a profile puts its bin in that profile's `node_modules/.bin`, which is not on
`PATH`:

```sh
"$DSH_HOME/profiles/<name>/node_modules/.bin/dsh-netguard" report
```

## Known limitations

`bash`, `run_code`, terminals, MCP servers and delegated agents are not governed. The model
channel is not governed. The spool is not rotated. The wildcard check uses a documented
approximation rather than a public suffix list. Without a `search.delegate`, result URLs are not
filtered — only the outbound query.

[All known limitations →](https://charlotten7.github.io/dsh-netguard/limitations.html)

## Development

```sh
nvm use 22           # Node ^22.19.0 || >=24, and pnpm 11
pnpm install
pnpm run typecheck
pnpm run test
pnpm run test:coverage
pnpm run test:e2e    # boots a real dsh against a mock model; no API key
```

Coverage is gated at 100% per file: this is a security control, so an arm nothing exercises is an
arm nobody has checked.

Design decisions and their rationale live in [ADR.md](ADR.md). Security policy is in
[SECURITY.md](SECURITY.md).

## License

MIT
