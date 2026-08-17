---
title: Overview
nav_order: 1
---

# Overview

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

**Five paths stay open with a perfect allowlist.**

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
5. **Search results on a stock profile.** The guarded search provider wraps a vendor provider
   named in `search.delegate`. Without one it reports itself unusable — which is what keeps
   this plugin from breaking a profile's existing search route — and the vendor the seam
   selected answers the seam directly. Only the outbound query is filtered; the result URLs
   reach the model unfiltered.

What it is good for, stated as narrowly as it is true:

- **It prevents accidents on the two tools it governs.** A `web_fetch` to a hallucinated URL, a
  `web_fetch` at an internal address, a `web_search` steering at a host you deny — these stop,
  and you see them. **A build script phoning home does not stop, and neither does a
  dependency's postinstall fetching a second stage**: both are `bash`, which this package
  cannot see. Stopping those needs the sandbox or a network-layer control.
- **It raises the cost of an injected agent** that asks a tool to fetch a URL.
- **It answers "which tool call opened this connection"** whenever the join lands, because
  every record carries the same `correlation_uid` scheme `dsh-ocsf-forwarder` stamps on its
  Process Activity records. The join is minted in the tool guard and looked up by the provider,
  and it is bounded and lossy on purpose: a record whose call it could not match carries no
  `correlation_uid` rather than a guessed one.

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

## Next

- [Install and compose](install.md)
- [Configuration](configuration.md)
- [What enforcement means](enforcement.md)
- [What it records](records.md)
- [Known limitations](limitations.md)
