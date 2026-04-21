package aaf

import (
    "encoding/json"
    "fmt"
    "path/filepath"
    "sort"
    "strings"
)

func Render(result ScanResult, format string) (string, error) {
    normalized := normalizeScanResult(result)
    switch strings.ToLower(format) {
    case "", "text":
        return renderText(normalized), nil
    case "json":
        return renderJSON(normalized)
    case "markdown", "md":
        return renderMarkdown(normalized), nil
    case "sarif":
        return renderSARIF(normalized)
    default:
        return "", fmt.Errorf("unsupported format: %s", format)
    }
}

func renderText(result ScanResult) string {
    var b strings.Builder
    fmt.Fprintf(&b, "%s\n\n", result.Tool)
    fmt.Fprintf(&b, "Target: %s\n", result.Target)
    fmt.Fprintf(&b, "Decision: %s\n", strings.ToUpper(result.Decision))
    fmt.Fprintf(&b, "Risk score: %d\n", result.RiskScore)
    fmt.Fprintf(&b, "CI fail: %s\n\n", yesNo(result.ShouldFail))
    fmt.Fprintf(&b, "Artifacts scanned: %d\n", len(result.Artifacts))
    fmt.Fprintf(&b, "Findings: %d\n", len(result.Findings))
    fmt.Fprintf(&b, "Parse errors: %d\n", parseErrorCount(result.Artifacts))

    if len(result.Findings) == 0 {
        return b.String()
    }

    b.WriteString("\nFindings\n")
    for _, f := range result.Findings {
        fmt.Fprintf(&b, "\n[%s] %s %s\n", strings.ToUpper(f.Severity), f.RuleID, f.Title)
        fmt.Fprintf(&b, "Path: %s\n", cleanPath(firstNonEmpty(f.RelativePath, f.Path)))
        if f.Evidence != "" {
            fmt.Fprintf(&b, "Evidence: %s\n", f.Evidence)
        }
        fmt.Fprintf(&b, "Why it matters: %s\n", f.Explanation)
        fmt.Fprintf(&b, "Recommendation: %s\n", f.Recommendation)
    }

    return b.String()
}

func renderJSON(result ScanResult) (string, error) {
    payload := orderedJSONObject{
        {Key: "target", Value: result.Target},
        {Key: "decision", Value: strings.ToUpper(result.Decision)},
        {Key: "score", Value: result.RiskScore},
        {Key: "should_fail", Value: result.ShouldFail},
        {Key: "artifacts_scanned", Value: len(result.Artifacts)},
        {Key: "findings_count", Value: len(result.Findings)},
        {Key: "parse_errors_count", Value: parseErrorCount(result.Artifacts)},
        {Key: "findings", Value: summarizeFindings(result.Findings)},
    }
    if len(result.Artifacts) > 0 {
        payload = append(payload, orderedField{Key: "artifacts", Value: summarizeArtifacts(result.Artifacts)})
    }
    return payload.MarshalIndented()
}

func renderMarkdown(result ScanResult) string {
    var b strings.Builder
    fmt.Fprintf(&b, "# AGENT-ARTIFACT-FIREWALL Report\n\n")
    fmt.Fprintf(&b, "Target: %s\n", result.Target)
    fmt.Fprintf(&b, "Decision: %s\n", strings.ToUpper(result.Decision))
    fmt.Fprintf(&b, "Risk score: %d\n", result.RiskScore)
    fmt.Fprintf(&b, "CI fail: %s\n\n", yesNo(result.ShouldFail))

    b.WriteString("## Summary\n\n")
    fmt.Fprintf(&b, "- Artifacts scanned: %d\n", len(result.Artifacts))
    fmt.Fprintf(&b, "- Findings: %d\n", len(result.Findings))
    fmt.Fprintf(&b, "- Parse errors: %d\n", parseErrorCount(result.Artifacts))

    if len(result.Findings) == 0 {
        return b.String() + "\n## Findings\n\nNo findings.\n"
    }

    b.WriteString("\n## Findings\n")
    for _, f := range result.Findings {
        fmt.Fprintf(&b, "\n### [%s] %s — %s\n", strings.ToUpper(f.Severity), f.RuleID, f.Title)
        fmt.Fprintf(&b, "- Path: %s\n", cleanPath(firstNonEmpty(f.RelativePath, f.Path)))
        if f.Evidence != "" {
            fmt.Fprintf(&b, "- Evidence: %s\n", f.Evidence)
        }
        fmt.Fprintf(&b, "- Why it matters: %s\n", f.Explanation)
        fmt.Fprintf(&b, "- Recommendation: %s\n", f.Recommendation)
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
            RuleID:    f.RuleID,
            Level:     sarifLevel(f.Severity),
            Message:   map[string]any{"text": fmt.Sprintf("%s: %s", f.Title, f.Evidence)},
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
            "properties": map[string]any{
                "target": result.Target,
                "decision": strings.ToUpper(result.Decision),
                "score": result.RiskScore,
                "should_fail": result.ShouldFail,
            },
            "results": results,
        }},
    }
    b, err := json.MarshalIndent(sarif, "", "  ")
    return string(b) + "\n", err
}

type orderedField struct {
    Key   string
    Value any
}

type orderedJSONObject []orderedField

func (o orderedJSONObject) MarshalIndented() (string, error) {
    var b strings.Builder
    b.WriteString("{\n")
    for i, field := range o {
        encoded, err := json.MarshalIndent(field.Value, "  ", "  ")
        if err != nil {
            return "", err
        }
        fmt.Fprintf(&b, "  %q: %s", field.Key, strings.TrimSpace(string(encoded)))
        if i < len(o)-1 {
            b.WriteString(",")
        }
        b.WriteString("\n")
    }
    b.WriteString("}\n")
    return b.String(), nil
}

func summarizeFindings(findings []Finding) []map[string]any {
    out := make([]map[string]any, 0, len(findings))
    for _, f := range findings {
        item := map[string]any{
            "rule_id":        f.RuleID,
            "title":          f.Title,
            "severity":       strings.ToLower(f.Severity),
            "relative_path":  cleanPath(firstNonEmpty(f.RelativePath, f.Path)),
            "explanation":    f.Explanation,
            "recommendation": f.Recommendation,
        }
        if f.Evidence != "" {
            item["evidence"] = f.Evidence
        }
        if f.Line > 0 {
            item["line"] = f.Line
        }
        out = append(out, item)
    }
    return out
}

func summarizeArtifacts(artifacts []Artifact) []map[string]any {
    out := make([]map[string]any, 0, len(artifacts))
    for _, a := range artifacts {
        item := map[string]any{
            "path":          cleanPath(firstNonEmpty(a.RelativePath, a.Path)),
            "type":          a.Type,
            "parser":        a.Parser,
            "has_parse_error": a.ParseError != "",
        }
        out = append(out, item)
    }
    return out
}

func normalizeScanResult(result ScanResult) ScanResult {
    normalized := result
    normalized.Artifacts = append([]Artifact(nil), result.Artifacts...)
    normalized.Findings = append([]Finding(nil), result.Findings...)

    sort.SliceStable(normalized.Artifacts, func(i, j int) bool {
        leftPath := cleanPath(firstNonEmpty(normalized.Artifacts[i].RelativePath, normalized.Artifacts[i].Path))
        rightPath := cleanPath(firstNonEmpty(normalized.Artifacts[j].RelativePath, normalized.Artifacts[j].Path))
        if leftPath == rightPath {
            return normalized.Artifacts[i].Type < normalized.Artifacts[j].Type
        }
        return leftPath < rightPath
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

func parseErrorCount(artifacts []Artifact) int {
    count := 0
    for _, a := range artifacts {
        if a.ParseError != "" {
            count++
        }
    }
    return count
}

func yesNo(v bool) string {
    if v {
        return "yes"
    }
    return "no"
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
