package aaf

import ("bufio"; "os"; "regexp"; "strings")

type rule struct { id, severity, title string; re *regexp.Regexp; explanation, recommendation string; applies func(Artifact) bool }

var builtinRules = []rule{
    {"AAF001", "high", "Hidden prompt injection or instruction override", regexp.MustCompile(`(?i)(ignore|override|bypass)\s+(all\s+)?(previous|prior|earlier|system|safety)\s+(instructions|rules|messages|checks)|<!--.*ignore.*instructions.*-->`), "Agent artifacts can influence model behavior through natural language instructions.", "Remove hidden override instructions and make expected behavior explicit.", nil},
    {"AAF003", "high", "Safety or approval bypass instruction", regexp.MustCompile(`(?i)(disable|bypass|skip)\s+(safety|approval|permission|review|guardrail)|run\s+without\s+(approval|asking|confirmation)`), "Agent artifacts should not instruct agents to bypass safety, approvals, or human review.", "Require explicit user approval for privileged or risky operations.", nil},
    {"AAF004", "high", "Credential file access", regexp.MustCompile(`(?i)(\.aws/credentials|\.netrc|\.npmrc|\.pypirc|\.docker/config\.json|credentials\.json)`), "Credential files often contain secrets that should not be read by installed agent artifacts.", "Use scoped environment variables, secret managers, or explicit credential delegation.", nil},
    {"AAF005", "high", ".env read attempt", regexp.MustCompile(`(?i)\b(cat|less|more|source|open|read|grep)\b[^\n;|&]*\.env\b|\.env\b`), ".env files frequently contain API keys and credentials.", "Avoid reading .env files from agent-installed scripts or hooks.", nil},
    {"AAF006", "critical", "SSH key access attempt", regexp.MustCompile(`(?i)(~/\.ssh|\.ssh/id_rsa|\.ssh/id_ed25519|id_rsa|id_ed25519)`), "Private SSH keys must not be read by untrusted agent artifacts.", "Remove private-key access and use explicit, scoped deployment credentials.", nil},
    {"AAF007", "high", "Plaintext secret in configuration", regexp.MustCompile(`(?i)"?[A-Z0-9_\-]*(API[_\-]?KEY|SECRET|TOKEN|PASSWORD)[A-Z0-9_\-]*"?\s*[:=]\s*"?[A-Za-z0-9_\.\-]{8,}`), "Plaintext secrets in agent, plugin, or MCP config can leak through repo history and logs.", "Replace raw values with environment variable references or a secret manager.", nil},
    {"AAF009", "high", "Remote script piped to shell", regexp.MustCompile(`(?i)(curl|wget)[^\n|;]*\|\s*(bash|sh)`), "Piping remote scripts directly to a shell makes provenance and integrity hard to verify.", "Pin downloads to immutable versions and verify checksums before execution.", nil},
    {"AAF011", "medium", "Hook command execution requires review", regexp.MustCompile(`(?i)(PostToolUse|PreToolUse|Stop|SubagentStop|"hooks"|"command"\s*:)`), "Hooks can execute during agent workflows and should be reviewed carefully.", "Restrict hook scope, require approval gates, and avoid secret/network access.", func(a Artifact) bool { return strings.Contains(strings.ToLower(a.Type), "hook") || strings.Contains(strings.ToLower(a.Path), "hook") || strings.Contains(strings.ToLower(a.Path), "plugin") }},
    {"AAF013", "high", "Potentially destructive shell command", regexp.MustCompile(`(?i)\brm\s+-rf\s+(/|~|\$HOME|\.\./|\*)|\bdd\s+if=|\bmkfs\b`), "Destructive commands can erase data or damage developer environments.", "Require explicit human approval and narrow command scope.", nil},
}

func evaluateRules(artifacts []Artifact) ([]Finding, error) {
    var findings []Finding
    for _, artifact := range artifacts {
        f, err := os.Open(artifact.Path); if err != nil { return nil, err }
        scanner := bufio.NewScanner(f); lineNo := 0
        for scanner.Scan() { lineNo++; line := scanner.Text(); for _, r := range builtinRules { if r.applies != nil && !r.applies(artifact) { continue }; if r.re.MatchString(line) { findings = append(findings, Finding{RuleID: r.id, Severity: r.severity, Title: r.title, Path: artifact.Path, Line: lineNo, Evidence: trimEvidence(line), Explanation: r.explanation, Recommendation: r.recommendation, Confidence: "medium"}) } } }
        if err := scanner.Err(); err != nil { _ = f.Close(); return nil, err }
        _ = f.Close()
    }
    return findings, nil
}

func trimEvidence(s string) string { s = strings.TrimSpace(s); if len(s) > 140 { return s[:137] + "..." }; return s }
