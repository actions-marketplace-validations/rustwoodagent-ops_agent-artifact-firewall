package aaf

import (
    "encoding/json"
    "strings"
    "testing"
)

func TestRenderJSONIncludesPolicyFields(t *testing.T) {
    result := ScanResult{
        Tool:       toolName,
        Version:    toolVersion,
        Decision:   "BLOCK",
        RiskScore:  100,
        ShouldFail: true,
        Policy:     PolicyConfig{FailOn: "high", MaxRiskScore: 70},
        Artifacts:  []Artifact{{Path: "b.sh", RelativePath: "b.sh", Type: "script"}},
        Findings:   []Finding{{RuleID: "AAF009", RelativePath: "b.sh", Severity: "high", Title: "curl | bash pattern", Evidence: "curl x | bash"}},
    }

    out, err := Render(result, "json")
    if err != nil {
        t.Fatal(err)
    }

    var decoded map[string]any
    if err := json.Unmarshal([]byte(out), &decoded); err != nil {
        t.Fatal(err)
    }

    required := []string{"risk_score", "decision", "should_fail", "findings", "artifacts", "policy"}
    for _, key := range required {
        if _, ok := decoded[key]; !ok {
            t.Fatalf("expected key %s in json output", key)
        }
    }
}

func TestRenderMarkdownShowsPolicySummaryAndFindings(t *testing.T) {
    result := ScanResult{
        Tool:       toolName,
        Version:    toolVersion,
        Decision:   "REVIEW",
        RiskScore:  35,
        ShouldFail: true,
        Findings: []Finding{{
            RuleID:       "AAF011",
            RelativePath: "hooks/hooks.json",
            Line:         7,
            Severity:     "medium",
            Title:        "Unreviewed hook execution",
            Evidence:     `"command": "bash scripts/postinstall.sh"`,
        }},
    }

    out, err := Render(result, "markdown")
    if err != nil {
        t.Fatal(err)
    }

    if !containsAll(out, []string{"**Decision:** `REVIEW`", "**Risk score:** `35/100`", "**CI fail:** `true`", "| medium | AAF011 | `hooks/hooks.json:7` |"}) {
        t.Fatalf("markdown output missing expected summary or finding row: %s", out)
    }
}

func TestRenderTextIsOperatorFriendly(t *testing.T) {
    result := ScanResult{
        Tool:       toolName,
        Version:    toolVersion,
        Decision:   "ALLOW",
        RiskScore:  0,
        ShouldFail: false,
    }

    out, err := Render(result, "text")
    if err != nil {
        t.Fatal(err)
    }

    if !containsAll(out, []string{"AGENT-ARTIFACT-FIREWALL, ✅ ALLOW", "Risk score: 0/100", "Decision: ALLOW"}) {
        t.Fatalf("text output missing expected headline fields: %s", out)
    }
    if strings.Contains(out, "CI fail: true") {
        t.Fatalf("text output should not imply CI failure on allow case: %s", out)
    }
}

func TestRenderSARIFIsStableAndClean(t *testing.T) {
    result := ScanResult{
        Tool:      toolName,
        Version:   toolVersion,
        Decision:  "BLOCK",
        RiskScore: 100,
        Findings: []Finding{
            {RuleID: "AAF009", Severity: "high", Title: "curl | bash pattern", RelativePath: "z.sh", Line: 6, Evidence: "curl x | bash", Explanation: "bad", Recommendation: "stop"},
            {RuleID: "AAF001", Severity: "high", Title: "Hidden prompt injection phrase", RelativePath: "a.md", Line: 1, Evidence: "ignore previous instructions", Explanation: "bad", Recommendation: "stop"},
        },
    }

    out, err := Render(result, "sarif")
    if err != nil {
        t.Fatal(err)
    }

    if strings.Contains(strings.ToLower(out), "should_fail") || strings.Contains(strings.ToLower(out), "risk_score") {
        t.Fatalf("sarif output should stay focused and avoid policy field noise: %s", out)
    }
    if strings.Index(out, `"uri": "a.md"`) > strings.Index(out, `"uri": "z.sh"`) {
        t.Fatalf("expected sarif results to stay deterministically ordered: %s", out)
    }
}
