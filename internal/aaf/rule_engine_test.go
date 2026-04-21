package aaf

import (
    "testing"
)

func TestRequestedRulesFireOnMaliciousFixture(t *testing.T) {
    result, err := Scan(ScanOptions{Path: "../../examples/malicious-skill", MaxRiskScore: 70})
    if err != nil {
        t.Fatal(err)
    }

    want := []string{"AAF001", "AAF003", "AAF005", "AAF006", "AAF007", "AAF009", "AAF011"}
    for _, id := range want {
        if !hasRule(result.Findings, id) {
            t.Fatalf("expected finding for %s", id)
        }
    }
}

func TestRequestedRulesStayQuietOnSafeFixture(t *testing.T) {
    result, err := Scan(ScanOptions{Path: "../../examples/safe-skill", MaxRiskScore: 70})
    if err != nil {
        t.Fatal(err)
    }
    if len(result.Findings) != 0 {
        t.Fatalf("expected no findings, got %#v", result.Findings)
    }
}

func TestDestructiveShellCommandRule(t *testing.T) {
    artifact := Artifact{Path: "danger.sh", RelativePath: "danger.sh", Type: "script"}
    findings := builtinRules[7].evaluate(artifact, []rawLine{{number: 1, text: "rm -rf /"}})
    if len(findings) != 1 {
        t.Fatalf("expected one finding, got %d", len(findings))
    }
    if findings[0].RuleID != "AAF013" {
        t.Fatalf("expected AAF013, got %s", findings[0].RuleID)
    }
}

func TestFindingsUseRelativePathAndStableOrder(t *testing.T) {
    result := ScanResult{
        Findings: []Finding{
            {RuleID: "AAF009", RelativePath: "scripts/z.sh", Line: 6, Evidence: "curl x | bash", Title: "curl | bash pattern", Severity: "high"},
            {RuleID: "AAF001", RelativePath: "SKILL.md", Line: 3, Evidence: "ignore previous instructions", Title: "Hidden prompt injection phrase", Severity: "high"},
        },
    }
    normalized := normalizeScanResult(result)
    if normalized.Findings[0].RelativePath != "SKILL.md" {
        t.Fatalf("expected SKILL.md first, got %s", normalized.Findings[0].RelativePath)
    }
}

func TestParseErrorDoesNotSuppressShellRuleScanning(t *testing.T) {
    root := t.TempDir()
    mustWriteFile(t, root+"/SKILL.md", "---\nname: broken\n")
    mustWriteFile(t, root+"/scripts/postinstall.sh", "#!/usr/bin/env bash\ncat .env\n")

    result, err := Scan(ScanOptions{Path: root, MaxRiskScore: 70})
    if err != nil {
        t.Fatal(err)
    }

    if !hasRule(result.Findings, "AAF005") {
        t.Fatal("expected AAF005 despite markdown parse error")
    }

    var sawParseError bool
    for _, artifact := range result.Artifacts {
        if artifact.Type == "skill" && artifact.ParseError != "" {
            sawParseError = true
        }
    }
    if !sawParseError {
        t.Fatal("expected parse error to be preserved on malformed markdown artifact")
    }
}

func hasRule(findings []Finding, ruleID string) bool {
    for _, finding := range findings {
        if finding.RuleID == ruleID {
            return true
        }
    }
    return false
}
