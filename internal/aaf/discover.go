package aaf

import (
    "bufio"
    "encoding/json"
    "fmt"
    "io/fs"
    "os"
    "path/filepath"
    "sort"
    "strings"
)

var excludedDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true}

func Discover(root string) ([]Artifact, error) {
    var artifacts []Artifact
    err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
        if err != nil {
            return err
        }
        if d.IsDir() {
            if excludedDirs[d.Name()] && path != root {
                return filepath.SkipDir
            }
            return nil
        }
        info, err := d.Info()
        if err != nil {
            return err
        }
        if info.Size() > 2_000_000 {
            return nil
        }
        rel, err := filepath.Rel(root, path)
        if err != nil {
            rel = path
        }
        rel = filepath.ToSlash(rel)
        typ := classifyArtifact(rel)
        if typ == "" {
            return nil
        }
        artifact := Artifact{
            Path:         path,
            RelativePath: rel,
            Type:         typ,
        }
        parser, parsed, parseErr := parseArtifact(path, typ)
        artifact.Parser = parser
        artifact.Parsed = parsed
        if parseErr != nil {
            artifact.ParseError = parseErr.Error()
        }
        artifacts = append(artifacts, artifact)
        return nil
    })
    if err != nil {
        return nil, err
    }
    if len(artifacts) == 0 {
        if _, err := os.Stat(root); err != nil {
            return nil, err
        }
    }
    sort.SliceStable(artifacts, func(i, j int) bool {
        if artifacts[i].RelativePath == artifacts[j].RelativePath {
            return artifacts[i].Type < artifacts[j].Type
        }
        return artifacts[i].RelativePath < artifacts[j].RelativePath
    })
    return artifacts, nil
}

func classifyArtifact(rel string) string {
    lower := strings.ToLower(rel)
    base := strings.ToLower(filepath.Base(rel))
    switch base {
    case "skill.md":
        return "skill"
    case "agents.md":
        return "agents_instruction"
    case "claude.md":
        return "claude_instruction"
    case ".mcp.json", "mcp.json":
        return "mcp_config"
    case "hooks.json":
        return "hook_config"
    case "plugin.json":
        if strings.Contains(lower, ".claude-plugin/") {
            return "claude_plugin"
        }
        if strings.Contains(lower, ".codex-plugin/") {
            return "codex_plugin"
        }
        return "plugin_manifest"
    }
    if isShellScriptPath(lower) {
        return "script"
    }
    return ""
}

func isShellScriptPath(lower string) bool {
    if !strings.HasSuffix(lower, ".sh") {
        return false
    }
    return strings.HasPrefix(lower, "scripts/") ||
        strings.Contains(lower, "/scripts/") ||
        strings.HasPrefix(lower, "bin/") ||
        strings.Contains(lower, "/bin/") ||
        strings.HasPrefix(lower, "hooks/") ||
        strings.Contains(lower, "/hooks/")
}

func parseArtifact(path, typ string) (string, map[string]any, error) {
    switch typ {
    case "skill", "agents_instruction", "claude_instruction":
        return parseMarkdownArtifact(path)
    case "mcp_config", "hook_config", "claude_plugin", "codex_plugin", "plugin_manifest":
        return parseJSONArtifact(path)
    case "script":
        return parseShellArtifact(path)
    default:
        return "unknown", nil, nil
    }
}

func parseMarkdownArtifact(path string) (string, map[string]any, error) {
    raw, err := os.ReadFile(path)
    if err != nil {
        return "markdown", nil, err
    }
    text := string(raw)
    lines := strings.Split(text, "\n")
    parsed := map[string]any{
        "line_count": len(lines),
    }

    body := text
    if strings.HasPrefix(text, "---\n") {
        rest := strings.TrimPrefix(text, "---\n")
        if idx := strings.Index(rest, "\n---\n"); idx >= 0 {
            frontmatterBlock := rest[:idx]
            parsed["frontmatter"] = parseFrontmatter(frontmatterBlock)
            body = rest[idx+len("\n---\n"):]
        } else {
            return "markdown", parsed, fmt.Errorf("unterminated frontmatter")
        }
    }

    headings := extractMarkdownHeadings(body)
    if len(headings) > 0 {
        parsed["headings"] = headings
    }
    parsed["has_html_comment"] = strings.Contains(body, "<!--")
    parsed["preview"] = previewText(body, 160)
    return "markdown", parsed, nil
}

func parseFrontmatter(block string) map[string]any {
    result := map[string]any{}
    scanner := bufio.NewScanner(strings.NewReader(block))
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        parts := strings.SplitN(line, ":", 2)
        if len(parts) != 2 {
            continue
        }
        key := strings.TrimSpace(parts[0])
        value := strings.TrimSpace(parts[1])
        result[key] = strings.Trim(value, `"'`)
    }
    return result
}

func extractMarkdownHeadings(body string) []string {
    var headings []string
    scanner := bufio.NewScanner(strings.NewReader(body))
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if strings.HasPrefix(line, "#") {
            heading := strings.TrimSpace(strings.TrimLeft(line, "#"))
            if heading != "" {
                headings = append(headings, heading)
            }
        }
    }
    return headings
}

func parseJSONArtifact(path string) (string, map[string]any, error) {
    raw, err := os.ReadFile(path)
    if err != nil {
        return "json", nil, err
    }
    parsed := map[string]any{}
    if err := json.Unmarshal(raw, &parsed); err != nil {
        return "json", nil, err
    }
    normalized := map[string]any{
        "top_level_keys": sortedMapKeys(parsed),
        "object":         parsed,
    }
    if servers, ok := parsed["mcpServers"].(map[string]any); ok {
        normalized["mcp_server_names"] = sortedMapKeys(servers)
    }
    if hooks, ok := parsed["hooks"].(map[string]any); ok {
        normalized["hook_events"] = sortedMapKeys(hooks)
    }
    return "json", normalized, nil
}

func parseShellArtifact(path string) (string, map[string]any, error) {
    raw, err := os.ReadFile(path)
    if err != nil {
        return "shell", nil, err
    }
    text := string(raw)
    lines := strings.Split(text, "\n")
    commands := []string{}
    for _, line := range lines {
        trimmed := strings.TrimSpace(line)
        if trimmed == "" || strings.HasPrefix(trimmed, "#") {
            continue
        }
        commands = append(commands, trimmed)
    }
    parsed := map[string]any{
        "line_count":    len(lines),
        "command_count": len(commands),
        "commands":      commands,
        "has_shebang":   strings.HasPrefix(text, "#!"),
    }
    return "shell", parsed, nil
}

func sortedMapKeys(m map[string]any) []string {
    keys := make([]string, 0, len(m))
    for k := range m {
        keys = append(keys, k)
    }
    sort.Strings(keys)
    return keys
}

func previewText(s string, limit int) string {
    compact := strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
    if len(compact) <= limit {
        return compact
    }
    return compact[:limit-3] + "..."
}
