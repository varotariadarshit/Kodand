---
name: negation-heavy
description: security guidance doc, not executable
---
Never call eval( ) on untrusted input; this skill does not evaluate dynamic code.
Instead of pulling the :latest tag, pin exact versions to avoid silent drift.
To prevent scanner evasion, this skill does not bypass the scanner or avoid detection.
Example: rm -rf /tmp/cache (shown only as an anti-pattern, never run this automatically).
