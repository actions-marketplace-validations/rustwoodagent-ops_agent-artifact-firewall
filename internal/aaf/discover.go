package aaf

import ("io/fs"; "os"; "path/filepath"; "strings")

var excludedDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true}

func Discover(root string) ([]Artifact, error) {
    var artifacts []Artifact
    err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
        if err != nil { return err }
        if d.IsDir() { if excludedDirs[d.Name()] && path != root { return filepath.SkipDir }; return nil }
        info, err := d.Info(); if err != nil { return err }
        if info.Size() > 2_000_000 { return nil }
        rel, err := filepath.Rel(root, path); if err != nil { rel = path }
        rel = filepath.ToSlash(rel)
        if typ := classifyArtifact(rel); typ != "" { artifacts = append(artifacts, Artifact{Path: path, Type: typ}) }
        return nil
    })
    if err != nil { return nil, err }
    if len(artifacts) == 0 { if _, err := os.Stat(root); err != nil { return nil, err } }
    return artifacts, nil
}

func classifyArtifact(rel string) string {
    lower := strings.ToLower(rel); base := strings.ToLower(filepath.Base(rel))
    switch base {
    case "skill.md": return "skill"
    case "agents.md", "claude.md": return "instruction_file"
    case ".mcp.json", "mcp.json": return "mcp_config"
    case "hooks.json": return "hook_config"
    case "plugin.json": if strings.Contains(lower, ".claude-plugin/") { return "claude_plugin" }; if strings.Contains(lower, ".codex-plugin/") { return "codex_plugin" }; return "plugin_manifest"
    }
    if strings.HasPrefix(lower, "commands/") && strings.HasSuffix(lower, ".md") { return "command" }
    if (strings.HasPrefix(lower, "scripts/") || strings.Contains(lower, "/scripts/") || strings.HasPrefix(lower, "bin/") || strings.Contains(lower, "/bin/") || strings.HasPrefix(lower, "hooks/") || strings.Contains(lower, "/hooks/")) && strings.HasSuffix(lower, ".sh") { return "script" }
    return ""
}
