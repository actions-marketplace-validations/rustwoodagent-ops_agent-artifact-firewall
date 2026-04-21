# AGENT-ARTIFACT-FIREWALL

> A firewall for AI agent artifacts.

**AGENT-ARTIFACT-FIREWALL** scans agent skills, plugins, hooks, MCP configs, repo instruction files, and install scripts before your agents execute them.

The CLI is `aaf`.

```bash
aaf scan .
```

## Why it exists

AI agents are becoming programmable through skills, plugins, hooks, MCP servers, slash commands, and repo instruction files. Those artifacts can carry hidden prompt injections, unsafe shell execution, plaintext secrets, risky MCP config, destructive commands, and credential exfiltration patterns.

> Before your agents run it, scan it.

## 30-second demo

```bash
go run ./cmd/aaf scan examples/malicious-skill
```

Expected result:

```text
AGENT-ARTIFACT-FIREWALL, ❌ BLOCK
Risk score: 100/100
```

Try the machine-readable outputs too:

```bash
go run ./cmd/aaf scan examples/malicious-skill --format json
go run ./cmd/aaf scan examples/malicious-skill --format sarif --out findings.sarif
```

## Quickstart

### Run from source

```bash
git clone https://github.com/rustwoodagent-ops/agent-artifact-firewall.git
cd agent-artifact-firewall
go build -o aaf ./cmd/aaf
./aaf scan examples/malicious-skill --no-fail
```

### Typical local usage

```bash
aaf scan .
aaf scan . --fail-on high
aaf scan . --format json
```

### CI and code scanning usage

```bash
aaf scan . --format sarif --out aaf.sarif
```

## CLI usage

```bash
aaf scan <path> [--format text|json|sarif|markdown] [--out file] [--fail-on low|medium|high|critical|none] [--max-risk-score N] [--no-fail]
```

## Supported artifact types

| Artifact type | Examples |
|---|---|
| Agent skills | `SKILL.md`, `.github/skills/**/SKILL.md`, `.claude/skills/**/SKILL.md`, `.codex/skills/**/SKILL.md` |
| Repo instructions | `AGENTS.md`, `CLAUDE.md` |
| MCP configs | `.mcp.json`, `mcp.json` |
| Hooks | `hooks.json`, files in `hooks/` |
| Plugins | `.claude-plugin/plugin.json`, `.codex-plugin/plugin.json` |
| Install and helper scripts | `scripts/*.sh`, `bin/*.sh`, `hooks/*.sh` |
| Slash and command docs | `commands/*.md` |

## Built-in rules

| Rule | Severity | Detects |
|---|---|---|
| `AAF001` | High | Hidden prompt injection or instruction override language |
| `AAF003` | High | Safety bypass or approval bypass instructions |
| `AAF004` | High | Access to credential files such as `.aws/credentials`, `.netrc`, `.npmrc` |
| `AAF005` | High | `.env` read or source attempts |
| `AAF006` | Critical | SSH key access such as `~/.ssh/id_rsa` |
| `AAF007` | High | Plaintext secrets in JSON, YAML, or env-like configuration |
| `AAF009` | High | `curl | bash` or `wget | sh` remote installer patterns |
| `AAF011` | Medium | Hook command execution that requires review |
| `AAF013` | High | Destructive shell commands |

## Decisions

| Score | Decision |
|---:|---|
| `0-29` | `allow` |
| `30-69` | `review` |
| `70-100` | `block` |

## Roadmap

### v0.1
- Deterministic scanner and artifact discovery
- Initial rule pack for prompt, secret, hook, MCP, and script risks
- Stable text and JSON findings output
- SARIF output for GitHub code scanning
- Demo fixtures for safe and malicious artifacts

### v0.2
- GitHub Action wrapper
- CI examples and dogfooding workflow
- Markdown report improvements
- Config and policy tuning controls

### v0.3
- More parser coverage across agent ecosystems
- Rule documentation and false-positive handling
- Trusted allowlists and suppressions
- Richer risk policy controls

### v1.0
- Stable CLI contract
- Stable finding schema for automation and downstream tooling
- Production-ready GitHub integration
- Broader artifact coverage across skills, plugins, hooks, MCP, and repo policy files

## License

MIT
