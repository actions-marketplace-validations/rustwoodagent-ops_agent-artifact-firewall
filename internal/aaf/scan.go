package aaf

import "strings"

const toolName = "AGENT-ARTIFACT-FIREWALL"
const toolVersion = "0.1.0-dev"

func Scan(opts ScanOptions) (ScanResult, error) { artifacts, err := Discover(opts.Path); if err != nil { return ScanResult{}, err }; findings, err := evaluateRules(artifacts); if err != nil { return ScanResult{}, err }; score := RiskScore(findings); return ScanResult{Tool: toolName, Version: toolVersion, Target: opts.Path, Decision: Decision(score, findings), RiskScore: score, Artifacts: artifacts, Findings: findings}, nil }
func RiskScore(findings []Finding) int { score := 0; for _, f := range findings { switch strings.ToLower(f.Severity) { case "critical": score += 40; case "high": score += 25; case "medium": score += 10; case "low": score += 3; default: score++ } }; if score > 100 { return 100 }; return score }
func Decision(score int, findings []Finding) string { for _, f := range findings { if strings.ToLower(f.Severity) == "critical" { return "block" } }; if score >= 70 { return "block" }; if score >= 30 { return "review" }; return "allow" }
func ShouldFail(result ScanResult, failOn string, maxRiskScore int) bool { if strings.ToLower(failOn) == "none" { return false }; if maxRiskScore > 0 && result.RiskScore >= maxRiskScore { return true }; threshold := severityRank(failOn); for _, finding := range result.Findings { if severityRank(finding.Severity) >= threshold { return true } }; return false }
func severityRank(s string) int { switch strings.ToLower(s) { case "critical": return 4; case "high": return 3; case "medium": return 2; case "low": return 1; default: return 999 } }
