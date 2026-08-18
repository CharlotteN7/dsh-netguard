---
title: What enforcement means
nav_order: 4
---

# What enforcement means

[← dsh-netguard docs](index.md)


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

**It records every call it sees, including the ones it cannot turn into a target.** Tool
arguments are model-authored JSON, so `url` can arrive as an array, a number, `null`, an object
with a `toString`, or text that is not a URL at all; each of those is denied in `enforce` mode
and recorded against a fixed marker — `(non-string-argument)`, `(unparsed-url)` — with a digest
of the argument beside it. A URL past `fetch.maxUrlLength` is a policy decision too, not a parse
failure: it is decided against the host it names, so padding a URL cannot reach a denied host
unrecorded. Only a call carrying no `url` or `query` key at all is passed over, because it names
no target and opens no socket.

### The search arms

The query is a real exfiltration sink: the query string *is* the payload, and it reaches the
vendor before any result comes back. What this package filters is the hosts named inside it, so
`site:attacker.example <secret>` does not go out. **A plain-text secret in a plain-text query
still reaches the vendor**, and no host policy changes that.

What counts as a host named in a query is a heuristic, and it is deliberately asymmetric. A
destination written as a URL, or after `site:` / `inurl:` / `link:`, is read as a host whatever
its top-level label. A **bare** dotted token in prose is only read as a host when its top-level
label is a delegated domain that is not also a common file extension — so `index.js`,
`readme.md`, `setup.py`, `asp.net` and `file.tar.gz` are words in a question rather than
destinations, and an ordinary developer query is not refused. A host read out of prose never
enters the host memory and never appears in `report --suggest`, because a word in a question is
not a connection anything made.

A query longer than `search.maxQueryLength` is refused rather than scanned: the hosts in it
cannot be enumerated inside a budget, and this scan runs synchronously inside the tool guard,
where the agent loop, the UI and every timer wait on it.

The vendor's transport is not ours to govern — every shipped provider calls bare global `fetch`
against its own configured `baseURL`. What is governed is the result: **in `enforce` mode** a
source whose host the policy denies is dropped before the model sees it, and the result comes back
marked truncated. A source URL that does not parse is dropped the same way, and recorded as
`(unparsed-source)` with a digest — a vendor string never becomes a hostname in a record. **In
`audit` mode every source reaches the model**, each refused one recorded with
`unmapped.dsh.enforced: false`: audit mode records, it does not remove.

The guarded search provider wraps a vendor provider named in `search.delegate`, imported at
first use. **Without a delegate it reports itself unusable**, so the profile's own search route
keeps working and only the outbound-query guard applies.

### Denial reasons

A closed vocabulary, borrowed from Codex, so the model gets something it can act on rather than
a timeout:

`blocked-by-allowlist` · `blocked-by-denylist` · `blocked-by-private-address` ·
`blocked-by-scheme` · `blocked-by-credentials` · `blocked-by-redirect` ·
`blocked-by-url-length` · `blocked-by-invalid-url` · `blocked-by-invalid-argument` ·
`blocked-by-query-length`

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
