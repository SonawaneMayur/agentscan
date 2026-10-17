# Security policy

## Reporting a vulnerability

Please report security problems in agentscan privately, not in a public issue.

Use GitHub's private reporting:
[Report a vulnerability](https://github.com/SonawaneMayur/agentscan/security/advisories/new).

Include what you found, how to reproduce it, and the version you tested (`agentscan --version`).
You can expect an acknowledgement within 5 working days. Once a fix is released you'll be credited
in the changelog, unless you'd prefer not to be.

## What counts

- A config pattern that agentscan should flag but misses (a false negative in an existing rule)
- agentscan printing a secret it should have masked
- Anything that makes agentscan read, execute or send data it shouldn't. It is designed to only
  read config files locally and never execute servers or make network requests.

New rule ideas are welcome as regular issues.

## Supported versions

Only the latest release receives fixes.
