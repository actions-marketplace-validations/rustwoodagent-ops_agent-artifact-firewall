package aaf

import (
    "path/filepath"
    "strings"
    "testing"
)

func TestSeverityWeights(t *testing.T) {
    cases := map[string]int{
        "info": 1,
        "low": 3,
        "medium": 10,
        "high": 25,
        "critical": 40,
    }
    for severity, want := range cases {
        if got := severityWeight(severity); got != want {
            t.Fatalf("severity %s: expected %d, got %d", severity, want, got)
        }
    }
}

func TestDecisionBoundaries(t *testing.T) {
    cases := []struct {
        score int
        want  string
    }{
        {0, "allow"},
        {29, "allow"},
        {30, "review"},
        {69, "review"},
        {70, "block"},
        {100, "block"},
    }
    for _, tc := range cases {
        if got := decisionForScore(tc.score); got != tc.want {
            t.Fatalf("score %d: expected %s, got %s", tc.score, tc.want, got)
        }
    }
}

func TestShouldFailThresholdBehaviour(t *testing.T) {
    result := ScanResult{RiskScore: 25, Findings: []Finding{{Severity: "medium"}}}
    if !ShouldFail(result, "medium", 70) {
        t.Fatal("expected fail on medium threshold")
    }
    if ShouldFail(result, "high", 70) {
        t.Fatal("did not expect fail on high threshold")
    }
    if !ShouldFail(ScanResult{RiskScore: 71}, "none", 70) {
        t.Fatal("expected fail on risk score threshold")
    }
}

func TestPolicyConfigOverrideFromAAFYml(t *testing.T) {
    root := t.TempDir()
    mustWriteFile(t, filepath.Join(root, ".aaf.yml"), "version: 1\n\ndecision:\n  fail_on: medium\n  max_risk_score: 55\n")
    cfg, err := loadPolicyConfig(root)
    if err != nil {
        t.Fatal(err)
    }
    if cfg.FailOn != "medium" {
        t.Fatalf("expected fail_on medium, got %s", cfg.FailOn)
    }
    if cfg.MaxRiskScore != 55 {
        t.Fatalf("expected max_risk_score 55, got %d", cfg.MaxRiskScore)
    }
}

func TestScanUsesPolicyConfigOverrides(t *testing.T) {
    root := t.TempDir()
    mustWriteFile(t, filepath.Join(root, ".aaf.yml"), "version: 1\n\ndecision:\n  fail_on: none\n  max_risk_score: 10\n")
    mustWriteFile(t, filepath.Join(root, "scripts", "postinstall.sh"), "#!/usr/bin/env bash\ncat .env\n")

    result, err := Scan(ScanOptions{Path: root})
    if err != nil {
        t.Fatal(err)
    }
    if result.Policy.FailOn != "none" {
        t.Fatalf("expected fail_on none, got %s", result.Policy.FailOn)
    }
    if result.Policy.MaxRiskScore != 10 {
        t.Fatalf("expected max_risk_score 10, got %d", result.Policy.MaxRiskScore)
    }
    if !result.ShouldFail {
        t.Fatal("expected should_fail true from max_risk_score override")
    }
}

func TestConfigDoesNotOverrideExplicitOptions(t *testing.T) {
    root := t.TempDir()
    mustWriteFile(t, filepath.Join(root, ".aaf.yml"), "version: 1\n\ndecision:\n  fail_on: none\n  max_risk_score: 10\n")
    mustWriteFile(t, filepath.Join(root, "scripts", "postinstall.sh"), "#!/usr/bin/env bash\ncat .env\n")

    result, err := Scan(ScanOptions{Path: root, FailOn: "critical", MaxRiskScore: 99})
    if err != nil {
        t.Fatal(err)
    }
    if result.Policy.FailOn != "critical" {
        t.Fatalf("expected explicit fail_on critical, got %s", result.Policy.FailOn)
    }
    if result.Policy.MaxRiskScore != 99 {
        t.Fatalf("expected explicit max_risk_score 99, got %d", result.Policy.MaxRiskScore)
    }
}

func TestDefaultPolicyWhenConfigMissing(t *testing.T) {
    root := t.TempDir()
    cfg, err := loadPolicyConfig(root)
    if err != nil {
        t.Fatal(err)
    }
    if cfg.FailOn != "high" || cfg.MaxRiskScore != 70 {
        t.Fatalf("unexpected default policy: %#v", cfg)
    }
}

func TestRenderPolicyVisibilityStable(t *testing.T) {
    result := ScanResult{
        Tool:       toolName,
        Version:    toolVersion,
        Decision:   "REVIEW",
        RiskScore:  35,
        ShouldFail: true,
        Policy:     PolicyConfig{FailOn: "medium", MaxRiskScore: 70},
    }
    out, err := Render(result, "text")
    if err != nil {
        t.Fatal(err)
    }
    if !containsAll(out, []string{"Risk score: 35/100", "Decision: REVIEW", "CI fail: true"}) {
        t.Fatalf("missing policy visibility fields in output: %s", out)
    }
}

func containsAll(s string, needles []string) bool {
    for _, needle := range needles {
        if !strings.Contains(s, needle) {
            return false
        }
    }
    return true
}
