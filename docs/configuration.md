---
title: Configuration
nav_order: 3
---

# Configuration

[← dsh-netguard docs](index.md)


```yaml
- id: dsh-netguard
  name: 'dsh-netguard'
  config:
    mode: audit                          # or enforce
    allow: ['**.github.com', '*.example.com', 'registry.npmjs.org:443']
    deny: ['*.internal.example']
    allowPrivateAddresses: []            # CIDR blocks; see below
    policyFile: ./.dsh-netguard.yml      # optional, lowest trust
    spoolPath: /var/log/dsh/netguard.ocsf.jsonl    # absolute; the host memory sits beside it
    hostMemoryPath: /var/log/dsh/netguard.hosts    # absolute; default <spoolPath>.hosts
    fetchProviderId: dsh-netguard        # what web.fetchProvider has to name
    searchProviderId: dsh-netguard       # what web.searchProvider would have to name
    vendorName: dsh-security-plugins     # metadata.product.vendor_name
    extension:
      name: dsh                          # keys the extension-owned attributes object
      placement: unmapped                # or `attribute`, which puts it at the top level
      uid: 999                           # omit until the OCSF registry assigns you one
    fetch:
      enabled: true
      timeoutMs: 30000
      maxRedirects: 5
      maxResponseBytes: 5000000
      maxBodyChars: 100000
      maxUrlLength: 2048
      # default: dsh-netguard/<this package's version> (+the repository URL)
      userAgent: 'acme-agent/2.0'
    search:
      enabled: true
      maxQueryLength: 2048               # past this a query is denied unscanned
      delegate:                          # absent = the search provider stays unusable
        module: '@deepseek-ai/dsh-web-search-exa'
        export: 'ExaSearchProvider'
        options: { apiKey: '...', baseURL: 'https://api.exa.ai', searchType: auto, highlightsPerResult: 1 }
    alerts:
      distinctUrlsPerHost: 32            # per session, per host; 0 turns the signal off
    hmacKey: { source: ephemeral }       # or { source: env, variable: NETGUARD_KEY }
    fleet:
      tenantUid: acme
      labels: [prod]
      tags: { team: security }           # metadata.tags[]
      installUid: laptop-7               # skips the sidecar entirely when you set it
      installUidPath: /var/log/dsh/netguard.install-uid   # absolute; default $DSH_HOME/install-uid
```

**Every path is required to be absolute.** A relative one resolves against the process's working
directory, which for `dsh` is the workspace — the same directory the repo-local policy tier is
defended against — so a relative `spoolPath` puts the audit trail somewhere the agent it records
can rewrite. A relative path fails the mount.

**Two sidecar files are created on first use:**

| File | Holds | Matters because |
|---|---|---|
| `<spoolPath>.hosts` | every host seen, with first/last sighting and counts | `is_alert` on a first-seen host, and `report --suggest` |
| `$DSH_HOME/install-uid` | one minted UUID | `device.uid`, which is stable across a rename and unique across a fleet imaged from one template |

The uid sits under the harness home rather than beside the spool because `dsh-ocsf-forwarder`
spools elsewhere and reads the same file: one machine has to report one `device.uid`, or every SOC
query that groups by device splits this host in two. A uid a release up to `0.1.0` left at
`<spoolPath>.install-uid` is read on first run and written through to the new path, so upgrading
does not re-identify the host.

Point `logrotate` at the spool only. The two sidecars are rewritten in place rather than
appended to, and rotating them costs the installation its host memory and its `device.uid`:

```
/var/log/dsh/netguard.ocsf.jsonl {
  weekly
  rotate 8
  compress
  missingok
  notifempty
  copytruncate
}
```

Set `fleet.installUid` yourself and the uid sidecar is never written. A harness home this
process cannot write is reported on stderr and the logger and then continues with an
in-memory uid, because losing a stable `device.uid` is a smaller loss than refusing to mount.

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
| `example.com/org/repo` | that path and everything under it — **allow list only** |

**A deny match wins over every allow match**, across every configuration source. **An empty
allow list denies everything**, and that is what ships.

A pattern that could be read two ways is refused at load rather than widened. Refused:
a prefix wildcard (`prod*.blob.core.windows.net` — that namespace is self-service, so the
pattern matches names an attacker can register), a wildcard anywhere but at the front
(`a*b.example.com`, `*.*.internal.example`, `*.internal.*`), a wildcard over a top-level domain
(`*.com`), a wildcard over a common public suffix (`*.co.uk`), an unbracketed IPv6 literal, a
URL, or credentials. Only a leading `*.` or `**.` is a wildcard; anything else is a
load-time error, in a deny list as much as in an allow list.

### Path-scoped allow entries

`github.com/your-org/your-repo` is a meaningfully narrower grant than all of `github.com`, and
the widest entry you can write is exactly what you should not have to. An allow entry may
therefore carry a path:

```yaml
allow:
  - 'huggingface.co/your-org/your-model'
  - 'github.com/your-org/your-repo'
```

The rules are as narrow as the host grammar, for the same reason — an entry that could be read
two ways is refused at load:

| | |
|---|---|
| What it grants | the path itself and everything under it, ending on a **segment boundary**: `example.com/api` covers `/api` and `/api/v2`, never `/apiv2` |
| Case | **case-sensitive**, because only a URL's scheme and host are not. `example.com/Org` does not cover `/org` |
| Traversal | `.` and `..` are resolved by the URL parser before the decision, so a path cannot be climbed out of; a request percent-encoding a slash (`..%2f`) matches **no** path-scoped entry, because the origin server may split the segments differently than this package does |
| Query strings | not part of the grant. The decision is on the path alone, and a pattern carrying `?` is refused rather than silently ignored |
| Redirects | re-decided per hop, so a granted path cannot be used as an open redirector into one that is not |
| Deny entries | **host-only**. A path on a deny entry would refuse *less* than the same line without one, so it is a load-time error |

Also refused: a trailing slash (`example.com/api/` — one grant, one spelling), a wildcard inside
the path (`example.com/org/*`), a percent-encoded slash, a `.` or `..` segment (a request path
never carries one, so the entry would match nothing), a path on the bare `*`, and a path on an IP
address — `10.0.0.0/8` is a CIDR block in the field one above, and reading it as a path would be
a different policy from the one you wrote.

Two things a path-scoped entry does **not** do. A request to an allowed host outside its granted
path is refused as `blocked-by-allowlist`, the same reason as a host that is not listed at all —
the model is told to ask for the entry it needs, and the path never appears in the message or in
a record. And a **search query** that merely names the host is not refused: the query filter
decides whether the host is one this policy tolerates, and it has no path to decide. A result
URL from a search *is* decided against the path, because the model can hand it straight to
`web_fetch`. `report --suggest` is unaffected: it writes hosts, never paths.

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

### The distinct-URL signal

A host allowlist cannot see an exfiltration that only ever contacts an allowed host. The shape
CVE-2026-54316 uses is a covert storage channel (CWE-515): with `huggingface.co` allowlisted as a
bare hostname, the secret is carried by *which* of many URLs on that one host is requested, and
it is read back out of the vendor's own download counters. No response body is needed and no
refused host is ever named.

What is visible is the request count. Every full URL is already reduced to an HMAC digest, so
this package counts the **distinct URL digests per session, per host**, writes the count into
each record as `distinct_urls`, and sets `is_alert` once it reaches
`alerts.distinctUrlsPerHost`. No verdict changes: this is a signal, in the same place
`first_seen_host` is one.

The default of 32 is a judgement, not a measurement. It is well past an agent reading
documentation or a handful of a repository's files in one session, and inside the range a channel
carrying even a short secret needs — one request per byte puts a 32-byte token at exactly 32
requests. **A patient exfiltrator defeats it**: 20 URLs per session, or a channel split across
several allowed hosts, never reaches the threshold. Set it lower to catch more and page more
often, or to `0` to turn the alert off and keep the count.

Only the URL the model asked for is counted. A redirect target is the server's choice, so a
redirecting host cannot raise the alert on the agents that visit it. The counter holds digests,
never URLs, and it is capped the way the tool-call join is: 64 session-and-host pairs, 256
distinct URLs each, so a long session cannot grow it without limit — past those caps the count
saturates and the oldest pair is dropped.

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

Overlap is tested in both directions, which rules out an entry a deployment is likely to reach
for: `fd00:ec2::254/128` sits inside `fc00::/7`, so **IPv6 ULA cannot be opened wholesale** —
`allowPrivateAddresses: ['fc00::/7']` fails the mount, and so does `['fd00::/8']`. Name the prefix
the service actually sits on instead and it loads: `['fd12:3456:789a::/48']` does. The same holds
for any block wide enough to contain an absolute entry: `169.0.0.0/8` contains the link-local range
and two metadata endpoints, and `0.0.0.0/0` and `::/0` contain everything. That is the rule
working — a block that wide opens the metadata endpoint along with whatever you meant by it — and
the mount error names the block you overlapped, so the entry to write instead is a narrower one.

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
