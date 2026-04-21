# Scanner test matrix and implementation plan

## Goal

Turn **AGENT-ARTIFACT-FIREWALL** into a credible scanner for agent-related artifacts across MCP, skills, Codex, Claude, hooks, and instruction files, with a practical external validation story.

This document defines:
- the first useful external test matrix
- the highest-value rule gaps
- the minimum discovery expansion needed to hit real agent ecosystems
- a staged implementation order that preserves demo clarity and keeps false positives manageable

## What is true today

The project already has a solid baseline:
- working repo scan command: `aaf scan <path>`
- text, JSON, Markdown, and SARIF outputs
- GitHub Action integration
- 8 existing rules (`AAF001`, `AAF003`, `AAF005`, `AAF006`, `AAF007`, `AAF009`, `AAF011`, `AAF013`)

So the next problem is **not** "make a scanner exist".
The next problem is **coverage credibility**.

Current rules are strongest on:
- markdown instruction overrides
- shell-based secret access
- MCP JSON plaintext secrets
- hook execution
- destructive shell behavior

Current rules are still thin on:
- MCP server config conventions used in the wild
- typosquatting / provenance confusion
- dangerous filesystem server patterns
- environment dump patterns
- remote MCP trust-boundary patterns
- package metadata and outdated dependency signals

## Current external baseline

### Safe lab baseline: `appsecco/vulnerable-mcp-servers-lab`
- Repo: <https://github.com/appsecco/vulnerable-mcp-servers-lab>
- Current AAF result: **0 artifacts, 0 findings**
- Why this matters: this is a discovery failure, not proof the lab is clean

Observed repo surface:
- `9` `claude_config.json` files
- `7` `package.json` files
- `9` JavaScript entrypoints
- `2` Python entrypoints

Interpretation:
- AAF currently misses this lab almost entirely because discovery does not yet include `claude_config.json` or MCP server source entrypoints referenced by those configs.

### Safe lab baseline: `opena2a-org/damn-vulnerable-ai-agent`
- Repo: <https://github.com/opena2a-org/damn-vulnerable-ai-agent>
- Current AAF result: **11 artifacts, 4 findings**

Observed repo surface:
- `9` `mcp.json` files
- `2` `SKILL.md` files
- `14` shell scripts

Current AAF already catches:
- hardcoded API keys in `scenarios/prompt-to-lateral-movement/vulnerable/mcp.json`
- prompt-override language in `scenarios/unicode-stego-package/vulnerable/SKILL.md`

Interpretation:
- DVAA is already useful as a regression target today.
- It is the best immediate external validation target for MCP config plus instruction-file coverage.

## Test matrix

Use two lanes.

### Lane A, safe demo labs

These are the primary README/demo and fixture-extraction sources.

| Priority | Target | Why it matters | Surface we should scan | Current AAF state | What it should validate |
|---|---|---|---|---|---|
| P0 | `appsecco/vulnerable-mcp-servers-lab` | Best focused MCP security lab with clearly named scenarios | `claude_config.json`, `package.json`, JS/Python MCP entrypoints, scenario READMEs | Missed almost entirely | prompt injection, malicious tools, typosquatting, outdated packages, secrets/PII, code-exec risk |
| P1 | `opena2a-org/damn-vulnerable-ai-agent` | Broad AI-agent lab beyond pure MCP, good for instruction + config coverage | `mcp.json`, `SKILL.md`, shell scripts, scenario docs | Partially covered already | skills, MCP configs, path traversal, supply chain, memory override, prompt abuse |
| P1 | existing internal fixtures (`examples/safe-skill`, `examples/malicious-skill`) | Stable smoke tests and README screenshots | skill + MCP config | Fully local and deterministic | keep launch/demo stable while external matrix grows |

### Lane B, real-world public concerns

These are **relevance anchors**, not exploit fixtures.
Use them in docs and planning to justify rule families.
Do not overclaim beyond the cited public source.

| Priority | Public source | Why it matters | Detection implication |
|---|---|---|---|
| P0 | `github/github-mcp-server#844` — <https://github.com/github/github-mcp-server/issues/844> | Publicly documents prompt injection from a public repo issue leading to private repo leakage risk in GitHub MCP workflows | prioritize trust-boundary, repo-scope, and least-privilege checks for GitHub MCP usage |
| P0 | `github/github-mcp-server#1685` — <https://github.com/github/github-mcp-server/issues/1685> | Public request for deterministic restriction to specific private repositories, instead of relying on prompt obedience | add config/policy checks and docs around broad GitHub MCP access without repository scoping |
| P0 | `modelcontextprotocol/servers#3752` — <https://github.com/modelcontextprotocol/servers/issues/3752> | Public filesystem-server concern: unbounded path parameters, traversal risk, vague tool descriptions, prompt injection to arbitrary read/write | add filesystem-scope and traversal-oriented MCP rules |
| P0 | `modelcontextprotocol/servers#3986` — <https://github.com/modelcontextprotocol/servers/issues/3986> | Public example of a `get-env` tool returning full `process.env` with no filtering | add env-dump and high-sensitivity host-read rules |

## First rule matrix

Existing rules already cover baseline markdown/script hazards.
The next step is to add MCP-centric and provenance-centric rules.

### Existing rules worth keeping as-is
- `AAF001` hidden prompt injection phrase
- `AAF003` safety override instruction
- `AAF005` `.env` read attempt
- `AAF006` SSH key read attempt
- `AAF007` plaintext MCP secret
- `AAF009` `curl | bash`
- `AAF011` unreviewed hook execution
- `AAF013` destructive shell command

### Proposed next rules

| Rule | Category | Source targets | Initial implementation idea | Notes |
|---|---|---|---|---|
| `AAF014` | Prompt injection outside markdown | Appsecco indirect prompt injection labs, DVAA skill scenarios, MCP tool descriptions | Scan JSON `description` fields, config metadata, and linked JS/Python tool-description strings for override / hidden-instruction patterns | expand `AAF001` ideas beyond markdown only |
| `AAF015` | Namespace / provenance confusion | Appsecco typosquatting lab, DVAA `typosquatting-mcp` | Flag suspicious MCP server names and package names that are near-matches to known popular names, repeated-letter variants, or mismatches between server key and package/bin identity | keep heuristic conservative and review-grade rather than block-grade at first |
| `AAF016` | Filesystem traversal / arbitrary path surface | MCP servers issue `#3752`, DVAA path traversal scenarios | Detect filesystem MCP package references, traversal-friendly descriptions, unsafe path examples, and broad read/write/edit tool wording without directory-boundary language | good candidate for medium/high severity with evidence-rich output |
| `AAF017` | Environment / host secret dump | MCP servers issue `#3986`, Appsecco secrets/PII lab | Detect `process.env`, `os.environ`, `env` dumps, `JSON.stringify(process.env)`, or tools explicitly returning all env vars | high signal for MCP server source scans |
| `AAF018` | Remote MCP / untrusted content trust boundary | Appsecco remote indirect-prompt-injection and Wikipedia HTTP labs | Detect remote MCP over HTTP/SSE configs, untrusted remote content retrieval patterns, and wording that returns external content verbatim without sanitization notes | likely review severity first, not block |
| `AAF019` | Outdated / deprecated dependency risk | Appsecco outdated-packages lab | Parse `package.json` and flag obviously stale or deprecated high-risk packages (`request`, very old `lodash`, very old `axios`, etc.) | best as review severity unless tied to known criticals |
| `AAF020` | Dangerous tool / approval grant in JSON or config | DVAA MCP capability scenarios, malicious tools labs | Extend approval-bypass and high-risk tool checks into JSON configs, plugin manifests, and MCP server descriptors | broadens `AAF003` beyond markdown |
| `AAF021` | Integrity / identity mismatch | typosquatting / rug-pull scenarios | Flag mismatches between MCP server name, package name, binary name, and repository identity; also unpinned install sources or raw `main` branch installs | useful for supply-chain credibility |

## Discovery expansion required

The single biggest gap is discovery, not scoring.

### P0 discovery additions

Add support for these files:
- `claude_config.json`
- `.well-known/mcp.json`
- `package.json` when it clearly represents an MCP server or agent package
- MCP server entrypoints referenced by config, for example linked `index.js`, `server.py`, or similar

### Why this matters

Without this, AAF misses the strongest safe demo repo in the matrix.
That makes README demos weaker and makes the scanner look narrower than it is meant to be.

### Suggested approach

Keep discovery layered:
1. **Artifact layer**: instruction files, MCP configs, hooks, plugins, shell helpers
2. **Linked source layer**: only scan JS/TS/Python files that are referenced by discovered MCP configs or package manifests
3. **Optional metadata layer**: GitHub API lookups for archived status, stars, last update, or package provenance, only when explicitly enabled

This keeps noise down and avoids turning AAF into a generic SAST tool.

## Implementation phases

### Phase 1, make the matrix real
- add this matrix doc
- broaden discovery to include `claude_config.json` and `.well-known/mcp.json`
- add package-level MCP detection in `package.json`
- add unit tests proving Appsecco-style configs are discovered

### Phase 2, land the highest-signal MCP rules
Implement first:
1. `AAF015` namespace / provenance confusion
2. `AAF017` environment / host secret dump
3. `AAF016` filesystem traversal / arbitrary path surface
4. `AAF020` dangerous tool / approval grant in JSON or config

Reason:
- these have strong public relevance
- they produce clear demo output
- they keep false positives understandable

### Phase 3, polish demo flow
- keep `examples/malicious-skill` as the quick local demo
- add one extracted safe-lab fixture from Appsecco for typosquatting or secrets/PII
- add one extracted safe-lab fixture from DVAA for MCP config or skill override detection
- update README with:
  - one tiny local fixture demo
  - one safe lab demo
  - one “public relevance” section citing real-world public issues without overstating exploitation claims

## Recommended fixture strategy

Do **not** make CI depend on cloning live external repos for every test run.

Instead:
- use live external repos for manual validation and docs
- extract minimal, attributed fixtures into the repo for deterministic CI
- keep a small manifest of upstream source URLs so fixtures can be refreshed deliberately

This gives:
- reproducible tests
- stable screenshots
- faster CI
- cleaner false-positive debugging

## Recommended next implementation slice

If work starts immediately, the strongest sequence is:

1. **Discovery**
   - support `claude_config.json`
   - support `.well-known/mcp.json`
   - support MCP-ish `package.json`

2. **Rules**
   - `AAF015` namespace/provenance confusion
   - `AAF017` env dump / host secret exposure
   - `AAF016` filesystem traversal surface

3. **Fixtures**
   - extract one Appsecco typosquatting fixture
   - extract one Appsecco secrets/PII fixture
   - extract one DVAA MCP config fixture

4. **Docs**
   - README demo section using one safe lab fixture
   - public relevance section citing `github/github-mcp-server#844`, `github/github-mcp-server#1685`, `modelcontextprotocol/servers#3752`, and `modelcontextprotocol/servers#3986`

## Success criteria for the next milestone

Call the next milestone successful when all of the following are true:
- Appsecco lab is no longer a zero-artifact scan
- DVAA still scans cleanly through the current CLI path
- at least 3 new MCP-centric rules land with tests
- one safe-lab fixture produces clean, readable findings in terminal output
- README shows one reproducible local demo plus one safe external-lab demo
- docs cite at least 2 public real-world issue threads as relevance evidence

## Bottom line

The fastest path to credibility is:
- **expand discovery just enough to see the real ecosystem**
- **add a small number of high-signal MCP rules**
- **use safe labs for demos and public issues for relevance**

That gives AAF a believable story quickly, without turning it into a sprawling generic static-analysis project.
