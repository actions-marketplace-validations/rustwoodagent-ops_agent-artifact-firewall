package aaf

import (
    "bufio"
    "fmt"
    "os"
    "regexp"
    "sort"
    "strings"
)

type rule struct {
    id             string
    severity       string
    title          string
    explanation    string
    recommendation string
    applies        func(Artifact) bool
    evaluate       func(Artifact, []rawLine) []Finding
}

type rawLine struct {
    number int
    text   string
}

var builtinRules = []rule{
    {
        id:             "AAF001",
        severity:       "high",
        title:          "Hidden prompt injection phrase",
        explanation:    "Agent artifacts should not contain hidden prompt-injection language that overrides prior instructions.",
        recommendation: "Remove hidden override phrasing and make intended behavior explicit and reviewable.",
        applies:        isMarkdownLikeArtifact,
        evaluate:       evaluateRegexRule(regexp.MustCompile(`(?i)(ignore|override|bypass)\s+(all\s+)?(previous|prior|earlier|system|safety)\s+(instructions|rules|messages|checks)|<!--.*ignore.*instructions.*-->`)),
    },
    {
        id:             "AAF003",
        severity:       "high",
        title:          "Safety override instruction",
        explanation:    "Agent artifacts should not instruct agents to bypass approvals, safety checks, or human review.",
        recommendation: "Require explicit approval and remove language that weakens review or safety boundaries.",
        applies:        isMarkdownLikeArtifact,
        evaluate:       evaluateRegexRule(regexp.MustCompile(`(?i)(disable|bypass|skip)\s+(safety|approval|permission|review|guardrail)|run\s+without\s+(approval|asking|confirmation)`)),
    },
    {
        id:             "AAF005",
        severity:       "high",
        title:          ".env read attempt",
        explanation:    ".env files frequently contain API keys and credentials and should not be read by installed artifacts.",
        recommendation: "Remove .env reads from hooks and scripts and use explicit, scoped secret injection instead.",
        applies:        isShellArtifact,
        evaluate:       evaluateRegexRule(regexp.MustCompile(`(?i)\b(cat|less|more|source|open|read|grep)\b[^\n;|&]*\.env\b`)),
    },
    {
        id:             "AAF006",
        severity:       "critical",
        title:          "SSH key read attempt",
        explanation:    "Private SSH keys must not be accessed by untrusted agent artifacts.",
        recommendation: "Remove private-key access and use explicit, scoped credentials or deployment tokens.",
        applies:        isShellArtifact,
        evaluate:       evaluateRegexRule(regexp.MustCompile(`(?i)(~/\.ssh|\.ssh/id_rsa|\.ssh/id_ed25519|id_rsa|id_ed25519)`)),
    },
    {
        id:             "AAF007",
        severity:       "high",
        title:          "Plaintext MCP secret",
        explanation:    "Plaintext secrets in MCP configuration can leak via repo history, logs, or downstream tooling.",
        recommendation: "Replace raw secret values with environment references or a secret manager.",
        applies:        isMCPArtifact,
        evaluate:       evaluatePlaintextMCPSecret,
    },
    {
        id:             "AAF009",
        severity:       "high",
        title:          "curl | bash pattern",
        explanation:    "Piping remote content directly into a shell makes provenance and integrity hard to verify.",
        recommendation: "Pin downloads to immutable versions and verify checksums before execution.",
        applies:        isShellArtifact,
        evaluate:       evaluateRegexRule(regexp.MustCompile(`(?i)(curl|wget)[^\n|;]*\|\s*(bash|sh)`)),
    },
    {
        id:             "AAF011",
        severity:       "medium",
        title:          "Unreviewed hook execution",
        explanation:    "Hook execution should be reviewed carefully because it can run automatically during agent workflows.",
        recommendation: "Restrict hook scope, require approval gates, and avoid secret or network access in hook commands.",
        applies:        isHookArtifact,
        evaluate:       evaluateHookExecution,
    },
    {
        id:             "AAF013",
        severity:       "high",
        title:          "Destructive shell command",
        explanation:    "Destructive shell commands can erase data or damage developer environments.",
        recommendation: "Require explicit human approval and narrow command scope before allowing destructive commands.",
        applies:        isShellArtifact,
        evaluate:       evaluateRegexRule(regexp.MustCompile(`(?i)\brm\s+-rf\s+(/|~|\$HOME|\.\./|\*)|\bdd\s+if=|\bmkfs\b`)),
    },
}

func evaluateRules(artifacts []Artifact) ([]Finding, error) {
    var findings []Finding
    for _, artifact := range artifacts {
        lines, err := readArtifactLines(artifact.Path)
        if err != nil {
            return nil, err
        }
        for _, r := range builtinRules {
            if r.applies != nil && !r.applies(artifact) {
                continue
            }
            findings = append(findings, r.evaluate(artifact, lines)...)
        }
    }

    sort.SliceStable(findings, func(i, j int) bool {
        left := findings[i]
        right := findings[j]
        if left.RelativePath != right.RelativePath {
            return left.RelativePath < right.RelativePath
        }
        if left.Line != right.Line {
            return left.Line < right.Line
        }
        if left.RuleID != right.RuleID {
            return left.RuleID < right.RuleID
        }
        if left.Evidence != right.Evidence {
            return left.Evidence < right.Evidence
        }
        return left.Title < right.Title
    })

    return findings, nil
}

func evaluateRegexRule(re *regexp.Regexp) func(Artifact, []rawLine) []Finding {
    return func(artifact Artifact, lines []rawLine) []Finding {
        var findings []Finding
        for _, line := range lines {
            if re.MatchString(line.text) {
                findings = append(findings, newFinding(artifact, line.number, trimEvidence(line.text), "", "", "", ""))
            }
        }
        return findings
    }
}

func evaluatePlaintextMCPSecret(artifact Artifact, lines []rawLine) []Finding {
    secretPattern := regexp.MustCompile(`(?i)"?[A-Z0-9_\-]*(API[_\-]?KEY|SECRET|TOKEN|PASSWORD)[A-Z0-9_\-]*"?\s*:\s*"[^"$][^"]{7,}"`)
    var findings []Finding
    for _, line := range lines {
        if secretPattern.MatchString(line.text) {
            findings = append(findings, newFinding(artifact, line.number, trimEvidence(line.text), "", "", "", ""))
        }
    }
    return findings
}

func evaluateHookExecution(artifact Artifact, lines []rawLine) []Finding {
    eventPattern := regexp.MustCompile(`(?i)"(PostToolUse|PreToolUse|Stop|SubagentStop)"\s*:`)
    commandPattern := regexp.MustCompile(`(?i)"command"\s*:\s*"[^"]+"`)
    var findings []Finding
    for _, line := range lines {
        if eventPattern.MatchString(line.text) || commandPattern.MatchString(line.text) {
            findings = append(findings, newFinding(artifact, line.number, trimEvidence(line.text), "", "", "", ""))
        }
    }
    return findings
}

func newFinding(artifact Artifact, line int, evidence, ruleID, title, severity, explanation string) Finding {
    return Finding{
        RuleID:         firstNonEmpty(ruleID, currentRuleID()),
        Title:          firstNonEmpty(title, currentRuleTitle()),
        Severity:       firstNonEmpty(severity, currentRuleSeverity()),
        Path:           artifact.Path,
        RelativePath:   artifact.RelativePath,
        Line:           line,
        Evidence:       evidence,
        Explanation:    firstNonEmpty(explanation, currentRuleExplanation()),
        Recommendation: currentRuleRecommendation(),
    }
}

func readArtifactLines(path string) ([]rawLine, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    var lines []rawLine
    scanner := bufio.NewScanner(f)
    lineNo := 0
    for scanner.Scan() {
        lineNo++
        lines = append(lines, rawLine{number: lineNo, text: scanner.Text()})
    }
    if err := scanner.Err(); err != nil {
        return nil, err
    }
    return lines, nil
}

func isMarkdownLikeArtifact(a Artifact) bool {
    switch a.Type {
    case "skill", "agents_instruction", "claude_instruction":
        return true
    default:
        return false
    }
}

func isShellArtifact(a Artifact) bool {
    return a.Type == "script"
}

func isMCPArtifact(a Artifact) bool {
    return a.Type == "mcp_config"
}

func isHookArtifact(a Artifact) bool {
    return a.Type == "hook_config"
}

func trimEvidence(s string) string {
    s = strings.TrimSpace(s)
    if len(s) > 140 {
        return s[:137] + "..."
    }
    return s
}

func firstNonEmpty(values ...string) string {
    for _, v := range values {
        if strings.TrimSpace(v) != "" {
            return v
        }
    }
    return ""
}

var activeRule *rule

func currentRuleID() string {
    if activeRule == nil {
        return ""
    }
    return activeRule.id
}

func currentRuleTitle() string {
    if activeRule == nil {
        return ""
    }
    return activeRule.title
}

func currentRuleSeverity() string {
    if activeRule == nil {
        return ""
    }
    return activeRule.severity
}

func currentRuleExplanation() string {
    if activeRule == nil {
        return ""
    }
    return activeRule.explanation
}

func currentRuleRecommendation() string {
    if activeRule == nil {
        return ""
    }
    return activeRule.recommendation
}

func init() {
    for i := range builtinRules {
        ruleRef := &builtinRules[i]
        original := ruleRef.evaluate
        ruleRef.evaluate = func(artifact Artifact, lines []rawLine) []Finding {
            prev := activeRule
            activeRule = ruleRef
            defer func() { activeRule = prev }()
            findings := original(artifact, lines)
            for i := range findings {
                findings[i].RuleID = ruleRef.id
                findings[i].Title = ruleRef.title
                findings[i].Severity = ruleRef.severity
                findings[i].Explanation = ruleRef.explanation
                findings[i].Recommendation = ruleRef.recommendation
            }
            return findings
        }
    }
    if activeRule != nil {
        panic(fmt.Sprintf("unexpected active rule state: %s", activeRule.id))
    }
}
