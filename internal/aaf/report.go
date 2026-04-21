package aaf

import (
    "encoding/json"
    "fmt"
    "path/filepath"
    "sort"
    "strings"
)

func Render(result ScanResult, format string) (string, error) {
    switch strings.ToLower(format) {
    case "", "text":
        return renderText(result), nil
    case "json":
        normalized := normalizeScanResult(result)
        b, err := json.MarshalIndent(normalized, "", "  ")
        return string(b) + "\n", err
    case "markdown", "md":
        return renderMarkdown(normalizeScanResult(result)), nil
    case "sarif":
        return renderSARIF(normalizeScanResult(result))
    default:
        return "", fmt.Errorf("unsupported format: %s", format)
    }
}

func renderText(result ScanResult) string {
    result = normalizeScanResult(result)
    icon := "✅"
    if result.Decision == "review" {
        icon = "⚠️"
    }
    if result.Decision == "block" {
        icon = "❌"
    }

    var b strings.Builder
    fmt.Fprintf(&b, "%s, %s %s\n", result.Tool, icon, strings.ToUpper(result.Decision))
    fmt.Fprintf(&b, "Risk score: %d/100\n", result.RiskScore)
    fmt.Fprintf(&b, "Artifacts found: %d\n", len(result.Artifacts))
    fmt.Fprintf(&b, "Findings: %d\n", len(result.Findings))

    if len(result.Artifacts) > 0 {
        b.WriteString("\nArtifacts:\n")
        for _, a := range result.Artifacts {
            fmt.Fprintf(&b, "  - %s (%s)\n", cleanPath(a.Path), a.Type)
        }
    }

    if len(result.Findings) > 0 {
        b.WriteString("\nFindings:\n")
        for _, f := range result.Findings {
            fmt.Fprintf(&b, "\n%s %s %s\n", strings.ToUpper(f.Severity), f.RuleID, f.Title)
            fmt.Fprintf(&b, "  File: %s:%d\n", cleanPath(firstNonEmpty(f.RelativePath, f.Path)), f.Line)
            if f.Evidence != "" {
                fmt.Fprintf(&b, "  Evidence: %s\n", f.Evidence)
            }
            fmt.Fprintf(&b, "  Why: %s\n", f.Explanation)
            fmt.Fprintf(&b, "  Fix: %s\n", f.Recommendation)
        }
    }

    return b.String()
}

func renderMarkdown(result ScanResult) string {
    var b strings.Builder
    fmt.Fprintf(&b, "# AGENT-ARTIFACT-FIREWALL Report\n\n**Decision:** `%s`  \n**Risk score:** `%d/100`  \n**Artifacts:** `%d`  \n**Findings:** `%d`\n\n", result.Decision, result.RiskScore, len(result.Artifacts), len(result.Findings))
    if len(result.Findings) == 0 {
        b.WriteString("No findings.\n")
        return b.String()
    }
    b.WriteString("| Severity | Rule | File | Evidence |\n|---|---|---|---|\n")
    for _, f := range result.Findings {
        fmt.Fprintf(&b, "| %s | %s | `%s:%d` | `%s` |\n", f.Severity, f.RuleID, cleanPath(firstNonEmpty(f.RelativePath, f.Path)), f.Line, escapeMarkdown(f.Evidence))
    }
    return b.String()
}

func renderSARIF(result ScanResult) (string, error) {
    type loc struct {
        PhysicalLocation struct {
            ArtifactLocation struct {
                URI string `json:"uri"`
            } `json:"artifactLocation"`
            Region struct {
                StartLine int `json:"startLine"`
            } `json:"region"`
        } `json:"physicalLocation"`
    }
    type sarifResult struct {
        RuleID    string         `json:"ruleId"`
        Level     string         `json:"level"`
        Message   map[string]any `json:"message"`
        Locations []loc          `json:"locations"`
    }
    type sarifRule struct {
        ID               string         `json:"id"`
        Name             string         `json:"name"`
        ShortDescription map[string]any `json:"shortDescription"`
        Help             map[string]any `json:"help"`
    }

    seen := map[string]sarifRule{}
    var results []sarifResult
    for _, f := range result.Findings {
        if _, ok := seen[f.RuleID]; !ok {
            seen[f.RuleID] = sarifRule{
                ID:   f.RuleID,
                Name: f.Title,
                ShortDescription: map[string]any{"text": f.Title},
                Help: map[string]any{"text": f.Explanation + " Recommendation: " + f.Recommendation},
            }
        }
        l := loc{}
        l.PhysicalLocation.ArtifactLocation.URI = cleanPath(firstNonEmpty(f.RelativePath, f.Path))
        if f.Line > 0 {
            l.PhysicalLocation.Region.StartLine = f.Line
        } else {
            l.PhysicalLocation.Region.StartLine = 1
        }
        results = append(results, sarifResult{
            RuleID:  f.RuleID,
            Level:   sarifLevel(f.Severity),
            Message: map[string]any{"text": fmt.Sprintf("%s: %s", f.Title, f.Evidence)},
            Locations: []loc{l},
        })
    }

    ruleIDs := make([]string, 0, len(seen))
    for id := range seen {
        ruleIDs = append(ruleIDs, id)
    }
    sort.Strings(ruleIDs)
    rules := make([]sarifRule, 0, len(ruleIDs))
    for _, id := range ruleIDs {
        rules = append(rules, seen[id])
    }

    sarif := map[string]any{
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": []any{map[string]any{
            "tool": map[string]any{"driver": map[string]any{
                "name": result.Tool,
                "version": result.Version,
                "informationUri": "https://github.com/rustwoodagent-ops/agent-artifact-firewall",
                "rules": rules,
            }},
            "results": results,
        }},
    }
    b, err := json.MarshalIndent(sarif, "", "  ")
    return string(b) + "\n", err
}

func normalizeScanResult(result ScanResult) ScanResult {
    normalized := result
    normalized.Artifacts = append([]Artifact(nil), result.Artifacts...)
    normalized.Findings = append([]Finding(nil), result.Findings...)

    sort.SliceStable(normalized.Artifacts, func(i, j int) bool {
        if cleanPath(normalized.Artifacts[i].Path) == cleanPath(normalized.Artifacts[j].Path) {
            return normalized.Artifacts[i].Type < normalized.Artifacts[j].Type
        }
        return cleanPath(normalized.Artifacts[i].Path) < cleanPath(normalized.Artifacts[j].Path)
    })

    sort.SliceStable(normalized.Findings, func(i, j int) bool {
        left := normalized.Findings[i]
        right := normalized.Findings[j]
        leftPath := cleanPath(firstNonEmpty(left.RelativePath, left.Path))
        rightPath := cleanPath(firstNonEmpty(right.RelativePath, right.Path))
        if leftPath != rightPath {
            return leftPath < rightPath
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

    return normalized
}

func sarifLevel(severity string) string {
    switch strings.ToLower(severity) {
    case "critical", "high":
        return "error"
    case "medium":
        return "warning"
    default:
        return "note"
    }
}

func cleanPath(p string) string {
    p = filepath.ToSlash(p)
    if idx := strings.Index(p, "agent-artifact-firewall-bootstrap/"); idx >= 0 {
        return p[idx+len("agent-artifact-firewall-bootstrap/"):]
    }
    return p
}

func escapeMarkdown(s string) string {
    s = strings.ReplaceAll(s, "`", "'")
    s = strings.ReplaceAll(s, "|", "\\|")
    return s
}
