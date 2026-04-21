# Agent instructions for this repo

This repository builds **AGENT-ARTIFACT-FIREWALL**, a deterministic scanner for AI agent artifacts.

## Goals

- Keep the scanner deterministic by default.
- Do not execute untrusted scanned files.
- Prefer simple, inspectable rules before complex AI judgment.
- Make the local CLI and GitHub CI experience excellent.

## Common commands

```bash
go test ./...
go run ./cmd/aaf scan examples/safe-skill
go run ./cmd/aaf scan examples/malicious-skill --no-fail
go run ./cmd/aaf scan examples/malicious-skill --format json --no-fail
```
