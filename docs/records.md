---
title: What it records
nav_order: 5
---

# What it records

[← dsh-netguard docs](index.md)


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

A first-seen host for this installation, any denial audit mode let through, and a session that
has issued `alerts.distinctUrlsPerHost` or more distinct URLs against one host all set
`is_alert: true`. The last of those is a signal a host allowlist cannot produce on its own; the
count rides on every fetch record as `distinct_urls`, and what it does and does not catch is in
[the configuration reference](configuration.md).

**Nothing is ever appended to the session log.** `Session.append()` offers no way to set the
envelope's `ignorable` flag, so an out-of-repo event type is written without it and the user's
next resume throws `SessionFormatUnsupportedError` and refuses the whole session. This package
is read-side with respect to the log, and an E2E assertion checks that no row in it carries one
of our types.

Each record therefore carries its own identity. `metadata.correlation_uid = <session>:<callId>`
is `dsh-ocsf-forwarder`'s key unchanged, and it is the reason to run the two packages together:
the forwarder already emits Process Activity 1007 for every tool call, so the same key on a 4001
record answers *which tool call opened this connection* — at tool-call granularity, which no other
harness can do.

`metadata.uid` is deliberately **not** the forwarder's key. It is `<session>:netguard:<seq>`, where
`seq` counts this package's decisions in this process; a decision with no session behind it uses
`dsh-netguard` in the first slot. The forwarder's is `<session>:<seq>` over the session log's own
event sequence. Both start near 1 in the same session, so an un-namespaced key would make
`session-88:4` the identity of two unrelated records, and a SIEM following both READMEs —
"deduplicate on `metadata.uid`", "records from both packages can sit in one index" — would drop the
netguard one as a duplicate. The namespace sits in this package rather than in the forwarder's key
because the forwarder is the established emitter with records already in indexes; see ADR.md §18.

**When the join hits.** The provider is handed `{ url }` and nothing else, so the call id comes
from the tool guard, which notes `url → identity` for the provider to look up moments later, and
`turn`/`step` come from the `tool/call` session event. Both maps are bounded and lossy on
purpose — an unbounded map costs the agent its memory. A record the join missed carries
`dst_endpoint`, the verdict and the digests, but no `correlation_uid` and no `turn`; it is a
connection without a named cause rather than a wrong one.

### The privacy lane

Verbatim: **a validated hostname**, port, resolved IP address, verdict, matched rule id, tool
name. Digested: the full URL, any search query, and any string that was supposed to be a
hostname and is not — as `HMAC-SHA256(key, value)` truncated to 128 bits, with the length beside
it. The digest is stable, so a SIEM can still join on it; nobody reading the spool learns the
value. This mirrors `dsh-ocsf-forwarder`'s lane rule exactly, so records from both packages can
sit in one index without one of them being the leak — and `metadata.uid` is namespaced so that
sharing an index does not make one package's records look like duplicates of the other's.

"Validated" is the whole point of the word. `dst_endpoint.hostname`, `observables[].value` and
`message` only ever carry a plain host spelling (`[a-z0-9.:_-]`) or one of these markers, and
the value a marker stands in for rides as a digest in the extension attributes:

| Marker | Stands in for |
|---|---|
| `(query)` | a decision about a search query rather than about one target |
| `(non-string-argument)` | a `url` or `query` argument that was not a string |
| `(unparsed-url)` | text that is not a URL with a host this package can decide |
| `(unparsed-source)` | a vendor search result whose source URL does not parse |
| `(unrecordable-host)` | a hostname carrying characters a verbatim field may not hold |

That last one exists because WHATWG `URL` keeps `'`, `"`, a backtick, `$`, `;`, `,` and `{` in a
hostname. `report --suggest` applies the same rule again on the way out: it writes a host into
YAML only when it matches `[a-z0-9._-]+`, so nothing a vendor or a model chose can add a line to
the allow list you paste into `cordis.yml`.

```json
{
  "class_uid": 4001, "category_uid": 4, "type_uid": 400105,
  "activity_id": 5, "action_id": 2, "disposition_id": 2, "severity_id": 3, "status_id": 2,
  "is_alert": false, "time": 1755300000000,
  "message": "netguard refused paste.example: blocked-by-denylist",
  "metadata": {
    "product": { "name": "dsh-netguard", "vendor_name": "dsh-security-plugins", "version": "0.1.0" },
    "version": "1.9.0", "profiles": ["security_control", "host"],
    "log_provider": "deepseek-harness", "log_name": "netguard",
    "uid": "session-88:4", "correlation_uid": "session-88:call-2", "sequence": 4,
    "logged_time": 1755300000000
  },
  "dst_endpoint": { "hostname": "paste.example", "port": 443, "svc_name": "https" },
  "connection_info": { "direction_id": 2, "protocol_name": "tcp" },
  "firewall_rule": { "uid": "deny:paste.example", "name": "blocked-by-denylist" },
  "observables": [{ "name": "dst_endpoint.hostname", "type_id": 1, "value": "paste.example" }],
  "unmapped": { "dsh": {
    "v": 1, "kind": "fetch", "mode": "enforce", "verdict": "denied", "enforced": true,
    "reason": "blocked-by-denylist", "rule": "deny:paste.example", "tool": "web_fetch",
    "session_id": "session-88", "call_id": "call-2", "root_call_id": "call-2",
    "turn": 1, "step": 0, "decision_id": "netguard-…", "first_seen_host": false,
    "url_digest": "hmac-sha256:9f2a…", "url_length": 63, "has_query": true, "hop": 0,
    "distinct_urls": 4
  } }
}
```

`device` and `src_endpoint` are left out of that listing only for length; every record carries
both. `firewall_rule` appears only when a pattern decided the request, and its `name` is the
same reason the attributes carry — an allowlist denial names no rule, so it has no
`firewall_rule` at all.

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
