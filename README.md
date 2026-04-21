# AGENT-ARTIFACT-FIREWALL

> A firewall for AI agent artifacts.

**AGENT-ARTIFACT-FIREWALL** scans Agent Skills, Codex plugins, Claude Code plugins, MCP configs, hooks, slash commands, repo instruction files, and install scripts before your agents execute them.

The CLI is named `aaf`.

```bash
aaf scan .
```

## Why this exists

AI coding agents are becoming programmable through skills, plugins, hooks, MCP servers, and repo instruction files. Those artifacts can contain hidden prompt injections, unsafe shell scripts, plaintext secrets, risky MCP config, unreviewed hooks, destructive commands, and credential exfiltration patterns.

> Before your agents run it, scan it.

## 30-second demo

```bash
go run ./cmd/aaf scan examples/malicious-skill --no-fail
```

Expected result:

```text
AGENT-ARTIFACT-FIREWALL — ❌ BLOCK
Risk score: 100/100
```

## Install from source

```bash
git clone https://github.com/rustwoodagent-ops/agent-artifact-firewall.git
cd agent-artifact-firewall
go build -o aaf ./cmd/aaf
./aaf scan examples/malicious-skill --no-fail
```

## CLI usage

```bash
aaf scan <path> [--format text|json|sarif|markdown] [--out file] [--fail-on low|medium|high|critical|none]
```

## Supported artifact discovery

| Artifact | Examples |
|---|---|
| Agent Skills | `SKILL.md`, `.github/skills/**/SKILL.md`, `.claude/skills/**/SKILL.md`, `.codex/skills/**/SKILL.md` |
| Repo instructions | `AGENTS.md`, `CLAUDE.md` |
| MCP configs | `.mcp.json`, `mcp.json` |
| Hooks | `hooks.json`, files in `hooks/` |
| Plugins | `.claude-plugin/plugin.json`, `.codex-plugin/plugin.json` |
| Scripts | `scripts/*.sh`, `bin/*.sh`, `hooks/*.sh` |
| Commands | `commands/*.md` |

## Built-in rules

| Rule | Severity | Detects |
|---|---|---|
| `AAF001` | High | hidden prompt injection / instruction override language |
| `AAF003` | High | safety bypass or approval bypass instructions |
| `AAF004` | High | access to credential files such as `.aws/credentials`, `.netrc`, `.npmrc` |
| `AAF005` | High | `.env` read/source attempts |
| `AAF006` | Critical | SSH key access such as `~/.ssh/id_rsa` |
| `AAF007` | High | plaintext secrets in JSON/YAML/env-like configuration |
| `AAF009` | High | `curl | bash` or `wget | sh` remote installer patterns |
| `AAF011` | Medium | hook command execution requiring review |
| `AAF013` | High | destructive shell commands |

## Decisions

| Score | Decision |
|---:|---|
| `0–29` | `allow` |
| `30–69` | `review` |
| `70–100` | `block` |

## Roadmap

- v0.1: deterministic scanner, artifact discovery, first rule pack, terminal/JSON/SARIF/Markdown output, demo fixtures.
- v0.2: GitHub Action wrapper, PR comments, richer config support, rule docs.
- v0.3: `gh skill` wrapper, skill lockfile, MCP policy packs, trusted allowlists.

## License

MIT
