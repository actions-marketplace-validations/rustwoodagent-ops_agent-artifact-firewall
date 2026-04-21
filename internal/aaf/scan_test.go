package aaf

import (
    "encoding/json"
    "strings"
    "testing"
)

func TestMaliciousFixtureBlocks(t *testing.T) {
    result, err := Scan(ScanOptions{Path: "../../examples/malicious-skill", MaxRiskScore: 70})
    if err != nil {
        t.Fatal(err)
    }
    if result.Decision != "block" {
        t.Fatalf("expected block, got %s", result.Decision)
    }
    if result.RiskScore < 70 {
        t.Fatalf("expected score >= 70, got %d", result.RiskScore)
    }
    if len(result.Findings) == 0 {
        t.Fatal("expected findings")
    }
}

func TestSafeFixtureAllows(t *testing.T) {
    result, err := Scan(ScanOptions{Path: "../../examples/safe-skill", MaxRiskScore: 70})
    if err != nil {
        t.Fatal(err)
    }
    if result.Decision != "allow" {
        t.Fatalf("expected allow, got %s", result.Decision)
    }
}

func TestRenderJSON(t *testing.T) {
    result, err := Scan(ScanOptions{Path: "../../examples/safe-skill"})
    if err != nil {
        t.Fatal(err)
    }
    out, err := Render(result, "json")
    if err != nil {
        t.Fatal(err)
    }
    if out == "" || out[0] != '{' {
        t.Fatal("expected JSON object")
    }
}

func TestRenderJSONStableOrdering(t *testing.T) {
    result := ScanResult{
        Tool:      toolName,
        Version:   toolVersion,
        Decision:  "block",
        RiskScore: 100,
        Artifacts: []Artifact{
            {Path: "z-last.sh", Type: "script"},
            {Path: "a-first.md", Type: "skill"},
        },
        Findings: []Finding{
            {RuleID: "AAF009", Severity: "high", Title: "Remote script piped to shell", Path: "z-last.sh", Line: 4, Evidence: "curl x | bash"},
            {RuleID: "AAF001", Severity: "high", Title: "Hidden prompt injection or instruction override", Path: "a-first.md", Line: 2, Evidence: "ignore prior instructions"},
        },
    }

    out, err := Render(result, "json")
    if err != nil {
        t.Fatal(err)
    }

    var decoded ScanResult
    if err := json.Unmarshal([]byte(out), &decoded); err != nil {
        t.Fatal(err)
    }

    if got, want := decoded.Artifacts[0].Path, "a-first.md"; got != want {
        t.Fatalf("expected first artifact %q, got %q", want, got)
    }
    if got, want := decoded.Findings[0].RuleID, "AAF001"; got != want {
        t.Fatalf("expected first finding %q, got %q", want, got)
    }
}

func TestRenderSARIFHasStableRuleOrder(t *testing.T) {
    result := ScanResult{
        Tool:      toolName,
        Version:   toolVersion,
        Decision:  "block",
        RiskScore: 100,
        Findings: []Finding{
            {RuleID: "AAF009", Severity: "high", Title: "Remote script piped to shell", Path: "b.sh", Line: 3, Evidence: "curl x | bash", Explanation: "bad", Recommendation: "stop"},
            {RuleID: "AAF001", Severity: "high", Title: "Hidden prompt injection or instruction override", Path: "a.md", Line: 1, Evidence: "ignore prior instructions", Explanation: "bad", Recommendation: "stop"},
        },
    }

    out, err := Render(result, "sarif")
    if err != nil {
        t.Fatal(err)
    }

    if strings.Index(out, `"id": "AAF001"`) > strings.Index(out, `"id": "AAF009"`) {
        t.Fatal("expected SARIF rules to be sorted by id")
    }
}
