---
name: safe-test-helper
description: Helps an agent summarize test failures and suggest next commands.
---

# Safe Test Helper

Use this skill to inspect test output and suggest safe next steps.

Allowed behavior:

- read visible test logs
- suggest commands for a human to run
- explain failure causes

Disallowed behavior:

- do not read credentials
- do not modify files without approval
- do not call external services
