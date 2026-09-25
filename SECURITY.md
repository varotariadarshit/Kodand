# Security policy

Kodand is a security tool that reads untrusted code, so vulnerabilities in Kodand
itself are taken seriously.

## Reporting a vulnerability

Report it privately through GitHub:
**Security → Report a vulnerability** on this repository
([direct link](https://github.com/varotariadarshit/Kodand/security/advisories/new)).
Please don't open a public issue for a vulnerability.

Include what you can of:
- the affected version (`kodand version`) and component (CLI, web console, MCP server)
- steps or a minimal file/archive that reproduces it
- what an attacker gains

## What to expect

Kodand is maintained by one person, so these are good-faith targets rather than
guarantees:

| Step | Target |
| --- | --- |
| Acknowledge your report | within 7 days |
| Confirm or rule it out | within 14 days |
| Fix and publish an advisory (high or critical) | within 30 days of confirmation |

You'll be credited in the advisory unless you ask not to be.

## Supported versions

Only the latest `1.x` release gets security fixes.

## Scope

In scope:
- Anything a scanned repository, skill, MCP config or archive can do to the
  machine running Kodand (path traversal, archive extraction, code execution,
  reading files outside the scan)
- The web console: authentication, sessions, cross-site request forgery, XSS
  from scanned content, DNS rebinding
- The MCP server: reaching projects that weren't shared with MCP, or files
  outside a scan

Out of scope (please open a regular issue instead):
- A detection Kodand misses, or a false positive. Use the "Missed detection" or
  "False positive" issue templates.
- Running the console with `--allow-remote` on an untrusted network. It serves
  plain HTTP, and the README says to put it behind TLS yourself.
- Anything that needs an attacker to already have your OS account.
