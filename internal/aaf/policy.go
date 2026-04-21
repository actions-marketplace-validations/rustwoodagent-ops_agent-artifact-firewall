package aaf

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func defaultPolicyConfig() PolicyConfig {
	return PolicyConfig{
		FailOn:       "high",
		MaxRiskScore: 70,
	}
}

func loadPolicyConfig(root string) (PolicyConfig, error) {
	cfg := defaultPolicyConfig()
	path := filepath.Join(root, ".aaf.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	section := ""
	var currentSuppression *Suppression

	flushSuppression := func() error {
		if currentSuppression == nil {
			return nil
		}
		normalized, err := normalizeSuppression(*currentSuppression)
		if err != nil {
			return err
		}
		cfg.Suppressions = append(cfg.Suppressions, normalized)
		currentSuppression = nil
		return nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if !strings.HasPrefix(line, " ") && strings.HasSuffix(trimmed, ":") {
			if err := flushSuppression(); err != nil {
				return cfg, err
			}
			section = strings.TrimSuffix(trimmed, ":")
			continue
		}

		switch section {
		case "decision":
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			switch key {
			case "fail_on":
				cfg.FailOn = strings.ToLower(value)
			case "max_risk_score":
				if n, err := strconv.Atoi(value); err == nil {
					cfg.MaxRiskScore = n
				}
			}
		case "suppressions":
			if strings.HasPrefix(trimmed, "- ") {
				if err := flushSuppression(); err != nil {
					return cfg, err
				}
				currentSuppression = &Suppression{}
				trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
				if trimmed == "" {
					continue
				}
			}
			if currentSuppression == nil {
				continue
			}
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			switch key {
			case "rule_id":
				currentSuppression.RuleID = value
			case "path":
				currentSuppression.Path = value
			case "reason":
				currentSuppression.Reason = value
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return cfg, err
	}
	if err := flushSuppression(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func normalizeSuppression(s Suppression) (Suppression, error) {
	path, err := normalizeSuppressionPath(s.Path)
	if err != nil {
		return Suppression{}, err
	}
	reason := strings.TrimSpace(s.Reason)
	if reason == "" {
		return Suppression{}, fmt.Errorf("invalid suppression for %q: reason is required", s.Path)
	}
	normalized := Suppression{
		RuleID: strings.ToUpper(strings.TrimSpace(s.RuleID)),
		Path:   path,
		Reason: reason,
	}
	return normalized, nil
}

func normalizeSuppressionPath(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("invalid suppression: path is required")
	}
	if filepath.IsAbs(raw) {
		return "", fmt.Errorf("invalid suppression path %q: must be relative", raw)
	}
	if strings.HasSuffix(raw, "/**") {
		if strings.Count(raw, "*") != 2 {
			return "", fmt.Errorf("invalid suppression path %q: only trailing /** is supported", raw)
		}
		base := normalizeRelativePath(strings.TrimSuffix(raw, "/**"))
		if base == "" || base == "." || base == ".." || strings.HasPrefix(base, "../") {
			return "", fmt.Errorf("invalid suppression path %q: must stay within the scan root", raw)
		}
		if strings.Contains(base, "*") {
			return "", fmt.Errorf("invalid suppression path %q: only trailing /** is supported", raw)
		}
		return base + "/**", nil
	}
	if strings.Contains(raw, "*") {
		return "", fmt.Errorf("invalid suppression path %q: only trailing /** is supported", raw)
	}
	normalized := normalizeRelativePath(raw)
	if normalized == "" || normalized == "." || normalized == ".." || strings.HasPrefix(normalized, "../") {
		return "", fmt.Errorf("invalid suppression path %q: must stay within the scan root", raw)
	}
	return normalized, nil
}

func normalizeRelativePath(path string) string {
	cleaned := filepath.ToSlash(filepath.Clean(path))
	cleaned = strings.TrimPrefix(cleaned, "./")
	if cleaned == "." {
		return ""
	}
	return cleaned
}

func applySuppressions(findings []Finding, suppressions []Suppression) ([]Finding, []SuppressedFinding) {
	if len(suppressions) == 0 {
		return findings, nil
	}

	active := make([]Finding, 0, len(findings))
	suppressed := make([]SuppressedFinding, 0)
	for _, finding := range findings {
		matched := false
		normalizedPath := normalizeRelativePath(firstNonEmpty(finding.RelativePath, finding.Path))
		for _, suppression := range suppressions {
			if suppression.RuleID != "" && finding.RuleID != suppression.RuleID {
				continue
			}
			if !suppressionPathMatches(suppression.Path, normalizedPath) {
				continue
			}
			suppressed = append(suppressed, SuppressedFinding{
				Finding:     finding,
				Suppression: suppression,
			})
			matched = true
			break
		}
		if !matched {
			active = append(active, finding)
		}
	}
	return active, suppressed
}

func suppressionPathMatches(pattern, findingPath string) bool {
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return findingPath == prefix || strings.HasPrefix(findingPath, prefix+"/")
	}
	return findingPath == pattern
}

func severityWeight(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 40
	case "high":
		return 25
	case "medium":
		return 10
	case "low":
		return 3
	case "info":
		return 1
	default:
		return 0
	}
}

func decisionForScore(score int) string {
	switch {
	case score >= 70:
		return "block"
	case score >= 30:
		return "review"
	default:
		return "allow"
	}
}

func shouldFailWithPolicy(result ScanResult, policy PolicyConfig) bool {
	if strings.ToLower(policy.FailOn) != "none" {
		threshold := severityRank(policy.FailOn)
		for _, finding := range result.Findings {
			if severityRank(finding.Severity) >= threshold {
				return true
			}
		}
	}
	if policy.MaxRiskScore > 0 && result.RiskScore >= policy.MaxRiskScore {
		return true
	}
	return false
}
