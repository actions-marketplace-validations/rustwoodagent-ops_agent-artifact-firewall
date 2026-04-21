package aaf

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSeverityWeights(t *testing.T) {
	cases := map[string]int{
		"info":     1,
		"low":      3,
		"medium":   10,
		"high":     25,
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

func TestPolicyConfigLoadsSuppressions(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, ".aaf.yml"), "version: 1\n\ndecision:\n  fail_on: medium\n  max_risk_score: 55\n\nsuppressions:\n  - rule_id: aaf011\n    path: ./examples/malicious-skill/hooks/hooks.json\n    reason: intentional demo fixture\n  - path: examples/fixtures/../fixtures/**\n    reason: regression fixture directory\n")

	cfg, err := loadPolicyConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(cfg.Suppressions); got != 2 {
		t.Fatalf("expected 2 suppressions, got %d", got)
	}
	if got := cfg.Suppressions[0]; got.RuleID != "AAF011" || got.Path != "examples/malicious-skill/hooks/hooks.json" || got.Reason != "intentional demo fixture" {
		t.Fatalf("unexpected first suppression: %#v", got)
	}
	if got := cfg.Suppressions[1]; got.RuleID != "" || got.Path != "examples/fixtures/**" || got.Reason != "regression fixture directory" {
		t.Fatalf("unexpected second suppression: %#v", got)
	}
}

func TestApplySuppressionsUsesFirstMatchingRuleInConfigOrder(t *testing.T) {
	findings := []Finding{{
		RuleID:       "AAF011",
		RelativePath: "examples/fixtures/hooks/hooks.json",
		Severity:     "medium",
		Title:        "Hook command execution",
	}}
	suppressions := []Suppression{
		{Path: "examples/fixtures/**", Reason: "directory-wide suppression"},
		{RuleID: "AAF011", Path: "examples/fixtures/hooks/hooks.json", Reason: "more specific but later"},
	}

	active, suppressed := applySuppressions(findings, suppressions)
	if len(active) != 0 {
		t.Fatalf("expected no active findings, got %#v", active)
	}
	if len(suppressed) != 1 {
		t.Fatalf("expected 1 suppressed finding, got %#v", suppressed)
	}
	if got, want := suppressed[0].Suppression.Reason, "directory-wide suppression"; got != want {
		t.Fatalf("expected first matching suppression reason %q, got %q", want, got)
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
		Target:     ".",
		Decision:   "REVIEW",
		RiskScore:  35,
		ShouldFail: true,
		Policy:     PolicyConfig{FailOn: "medium", MaxRiskScore: 70},
	}
	out, err := Render(result, "text")
	if err != nil {
		t.Fatal(err)
	}
	if !containsAll(out, []string{"Target: .", "Decision: REVIEW", "Risk score: 35", "CI fail: yes"}) {
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
