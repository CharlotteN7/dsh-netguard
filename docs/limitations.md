---
title: Known limitations
nav_order: 6
---

# Known limitations

[← dsh-netguard docs](index.md)


- **`bash`, `run_code`, terminals, MCP servers and delegated agents are not governed.** Not a
  gap to be closed at this layer; it needs the sandbox.
- **The model channel is not governed**, and it is the dominant exfiltration path.
- **The spool is not rotated.** This package writes one record per decision — a few lines per
  session, not one per session event — so the file grows slowly. Point `logrotate` at the spool
  on a long-lived installation, and at neither sidecar; see the configuration section.
- **No public suffix list.** The wildcard check is a documented approximation; see the grammar
  section.
- **A query with no host in it is not filtered.** A host allowlist has nothing to decide there.
- **A bare host in prose is read by a heuristic.** A token ending in a top-level label this
  package does not list — or in one that is also a common file extension — is a word, not a
  destination. `site:`, `inurl:`, `link:` and a full URL are read as destinations regardless.
- **The tool-call join is bounded and lossy.** A record whose call the join could not match
  carries no `correlation_uid`; the two maps are capped so a long session cannot grow them
  without limit.
- **Without a `search.delegate`, result URLs are not filtered** — only the outbound query is
  checked, because the vendor provider the seam selected answers the seam directly and never
  passes through this package.
- **A fetch provider composed *after* this plugin is not detected at mount.** It surfaces as
  `WEB_PROVIDER_AMBIGUOUS` at the first `web_fetch` instead.
- **The mount check reads private fields** of the live `WebRuntime` (`fetchProviders`,
  `searchProviders`, `fetchProviderId`, `searchProviderId`). That is a deliberate coupling to a harness version; when a rename makes
  them unreadable, the check says it could not verify the composition and tells you to pin the
  provider explicitly rather than inventing a verdict. See [ADR.md](ADR.md).
- **`globalThis.fetch` is not patched and the undici global dispatcher is not touched.** Both
  were considered and rejected: the harness's own model traffic goes through the same function,
  so a deny arm bricks the agent and a log arm writes `x-api-key` and `Authorization` headers
  into the sink.
