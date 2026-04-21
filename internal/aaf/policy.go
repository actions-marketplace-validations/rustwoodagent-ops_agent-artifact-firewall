package aaf

import (
    "bufio"
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
    inDecision := false
    for scanner.Scan() {
        line := scanner.Text()
        trimmed := strings.TrimSpace(line)
        if trimmed == "" || strings.HasPrefix(trimmed, "#") {
            continue
        }

        if !strings.HasPrefix(line, " ") && strings.HasSuffix(trimmed, ":") {
            inDecision = trimmed == "decision:"
            continue
        }
        if !inDecision {
            continue
        }

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
    }
    if err := scanner.Err(); err != nil {
        return cfg, err
    }
    return cfg, nil
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
