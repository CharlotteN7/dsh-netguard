---
title: Install and compose
nav_order: 2
---

# Install and compose

[← dsh-netguard docs](index.md)

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

## Install

```sh
dsh plugin --profile <name> add @deepseek-ai/dsh-headless@0.1.0-rc.6
dsh plugin --profile <name> add dsh-netguard
dsh --profile <name> --dump-config      # the dsh-netguard row should appear
```

`@deepseek-ai/dsh-headless` is in that list because a profile carrying only `dsh-base` has no
agent loop. The base bundle inserts the service rows — model adapters, tools, persistence, the
web seam — and the headless bundle inserts the runner that creates an agent, submits one task,
and therefore makes the tool calls this package guards. Any other mode bundle does as well;
headless is the one the examples here use because it needs no terminal and no browser.

Pin it explicitly: its npm `latest` tag still points at `0.0.1-rc.1`, so an unpinned install
silently resolves to a much older harness.

Which harness versions this package accepts: the `@deepseek-ai/dsh-*` peer ranges are
`^0.1.0-rc.6`, so any release from that rc onwards in the `0.1.x` line satisfies them, and CI runs
the end-to-end suite against every published rc in that range. They are ranges rather than exact
pins because an exact pin makes `npm install dsh-netguard` fail outright once upstream publishes a
newer rc: `npm` refuses the tree when a transitively resolved harness package demands a version
the pin excludes. `@deepseek-ai/cordis` stays pinned at `4.0.1` — it is the object model every
plugin and the harness share, and two copies of it do not compose.

**Install from the registry or a packed tarball, not from a git spec.**
`dsh plugin add github:CharlotteN7/dsh-netguard` resolves and writes the dependency, but `lib/`
is a build output that git does not carry and no `prepare` script rebuilds it, so the row mounts
and then fails to load. To install from a checkout, build first and add the tarball:

```sh
git clone https://github.com/CharlotteN7/dsh-netguard && cd dsh-netguard
pnpm install && pnpm run build && pnpm pack       # prints the tarball it wrote
dsh plugin --profile <name> add ./dsh-netguard-0.3.0.tgz
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
quoting the patch above, character for character — a unit test compares the two. What the check
covers: a pin naming another provider, an unpinned composition that already has a usable one, a
registry it cannot read, and `web.searchProvider: dsh-netguard` with no `search.delegate`
configured, which would otherwise mount cleanly and then fail every search. What it cannot
cover is a fetch provider composed *after* this plugin: that one surfaces as
`WEB_PROVIDER_AMBIGUOUS` at the first `web_fetch`.
