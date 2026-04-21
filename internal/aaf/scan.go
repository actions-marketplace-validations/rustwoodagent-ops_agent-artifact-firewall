package aaf

import "strings"

const toolName = "AGENT-ARTIFACT-FIREWALL"
const toolVersion = "0.1.0-dev"

func Scan(opts ScanOptions) (ScanResult, error) {
	policy, err := loadPolicyConfig(opts.Path)
	if err != nil {
		return ScanResult{}, err
	}
	if opts.FailOn == "" {
		opts.FailOn = policy.FailOn
	}
	if opts.MaxRiskScore == 0 {
		opts.MaxRiskScore = policy.MaxRiskScore
	}

	artifacts, err := Discover(opts.Path)
	if err != nil {
		return ScanResult{}, err
	}
	findings, err := evaluateRules(artifacts)
	if err != nil {
		return ScanResult{}, err
	}
	activeFindings, suppressedFindings := applySuppressions(findings, policy.Suppressions)
	score := RiskScore(activeFindings)
	result := ScanResult{
		Tool:               toolName,
		Version:            toolVersion,
		Target:             opts.Path,
		Decision:           strings.ToUpper(decisionForScore(score)),
		RiskScore:          score,
		ShouldFail:         shouldFailWithPolicy(ScanResult{Findings: activeFindings, RiskScore: score}, PolicyConfig{FailOn: opts.FailOn, MaxRiskScore: opts.MaxRiskScore}),
		Policy:             PolicyConfig{FailOn: opts.FailOn, MaxRiskScore: opts.MaxRiskScore},
		Artifacts:          artifacts,
		Findings:           activeFindings,
		SuppressedFindings: suppressedFindings,
	}
	return result, nil
}

func RiskScore(findings []Finding) int {
	score := 0
	for _, f := range findings {
		score += severityWeight(f.Severity)
	}
	if score > 100 {
		return 100
	}
	return score
}

func Decision(score int, findings []Finding) string {
	for _, f := range findings {
		if strings.ToLower(f.Severity) == "critical" {
			return "BLOCK"
		}
	}
	return strings.ToUpper(decisionForScore(score))
}

func ShouldFail(result ScanResult, failOn string, maxRiskScore int) bool {
	return shouldFailWithPolicy(result, PolicyConfig{FailOn: failOn, MaxRiskScore: maxRiskScore})
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	case "none":
		return 0
	default:
		return 999
	}
}
