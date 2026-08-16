# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |
| < 0.1 | no |

Only the latest published `0.1.x` receives fixes. There is no long-term-support branch while
the package is pre-1.0.

## Reporting a vulnerability

Email **nsof@protonmail.com**. Please include:

- what an attacker gets — a connection to a host the policy should have refused, a URL or a
  query written into the spool, or a way to make the guard abstain;
- the smallest reproduction you have, ideally a failing test against this repository;
- the versions of `dsh-netguard`, DeepSeek Harness, and Node you ran.

Do not open a public issue for a vulnerability first.

**Response window:** acknowledgement within 3 working days, an assessment with a fix or a
rejection within 14 days. If a fix ships, the release notes credit the reporter unless asked
otherwise.

## What counts as a vulnerability here

This plugin is **not an egress firewall and not a containment boundary**. It governs
`web_fetch` and `web_search`, in-process, at the agent's own uid. The following are documented
limits, described in README.md and PLAN.md §6 — not vulnerabilities:

- anything sent by `bash`, `run_code`, a terminal session, an MCP server, or a delegated
  external agent, none of which this release sees;
- the model channel: a secret encoded into the agent's next prompt travels over the one
  connection the deployment must permit, and nothing here touches it;
- what an allowlisted destination itself permits — `github.com` on the allow list is the full
  GitHub API as whoever `gh` is authenticated as;
- images the DSH web UI renders from model-authored markdown: that request is made by the
  operator's browser, not by the agent's process;
- audit mode letting a request through. Audit mode is not a control; it is the default and the
  README says so in those words.

These do count, and we want to hear about them:

- a URL spelling that reaches a host the compiled policy should have refused — an encoding the
  canonicaliser misses, an IPv6 form that is not decompressed, a redirect that escapes the
  same-origin rule;
- a resolved address inside the refused table that a request still connects to, including any
  way to reach `169.254.169.254` or `168.63.129.16`;
- a DNS answer that changes between the check and the connect and still reaches the second
  answer;
- a full URL, a query string, or any other value outside the documented SOC lane written to the
  spool or to a log line;
- a repo-local `policyFile` that widens the policy, executes code, or stalls the agent;
- a composition in which this plugin mounts, reports no fault, and is then bypassed.
