package aaf

import (
    "os"
    "path/filepath"
    "testing"
)

func TestDiscoverDeterministicAndParsedArtifacts(t *testing.T) {
    root := t.TempDir()

    mustWriteFile(t, filepath.Join(root, "AGENTS.md"), "# Agent instructions\n")
    mustWriteFile(t, filepath.Join(root, "CLAUDE.md"), "# Claude instructions\n")
    mustWriteFile(t, filepath.Join(root, "skill", "SKILL.md"), "---\nname: helper\ndescription: desc\n---\n\n# Heading\nHello\n")
    mustWriteFile(t, filepath.Join(root, ".mcp.json"), `{"mcpServers":{"alpha":{"command":"node"}}}`)
    mustWriteFile(t, filepath.Join(root, "hooks", "hooks.json"), `{"hooks":{"PostToolUse":[]}}`)
    mustWriteFile(t, filepath.Join(root, ".claude-plugin", "plugin.json"), `{"name":"claude-safe"}`)
    mustWriteFile(t, filepath.Join(root, ".codex-plugin", "plugin.json"), `{"name":"codex-safe"}`)
    mustWriteFile(t, filepath.Join(root, "scripts", "install.sh"), "#!/usr/bin/env bash\necho ok\n")

    artifacts, err := Discover(root)
    if err != nil {
        t.Fatal(err)
    }

    if len(artifacts) != 8 {
        t.Fatalf("expected 8 artifacts, got %d", len(artifacts))
    }

    expectedOrder := []string{
        ".claude-plugin/plugin.json",
        ".codex-plugin/plugin.json",
        ".mcp.json",
        "AGENTS.md",
        "CLAUDE.md",
        "hooks/hooks.json",
        "scripts/install.sh",
        "skill/SKILL.md",
    }
    for i, rel := range expectedOrder {
        if artifacts[i].RelativePath != rel {
            t.Fatalf("expected artifact %d to be %q, got %q", i, rel, artifacts[i].RelativePath)
        }
    }

    skill := artifacts[7]
    if skill.Parser != "markdown" {
        t.Fatalf("expected markdown parser, got %q", skill.Parser)
    }
    if skill.ParseError != "" {
        t.Fatalf("unexpected skill parse error: %s", skill.ParseError)
    }
    frontmatter, ok := skill.Parsed["frontmatter"].(map[string]any)
    if !ok || frontmatter["name"] != "helper" {
        t.Fatalf("expected parsed frontmatter, got %#v", skill.Parsed["frontmatter"])
    }

    mcp := artifacts[2]
    if mcp.Parser != "json" {
        t.Fatalf("expected json parser, got %q", mcp.Parser)
    }
    if names, ok := mcp.Parsed["mcp_server_names"].([]string); !ok || len(names) != 1 || names[0] != "alpha" {
        t.Fatalf("expected mcp server names, got %#v", mcp.Parsed["mcp_server_names"])
    }

    script := artifacts[6]
    if script.Parser != "shell" {
        t.Fatalf("expected shell parser, got %q", script.Parser)
    }
    if script.Parsed["command_count"] != 1 {
        t.Fatalf("expected command_count 1, got %#v", script.Parsed["command_count"])
    }
}

func TestDiscoverMalformedArtifactsPreservesParseErrors(t *testing.T) {
    root := t.TempDir()

    mustWriteFile(t, filepath.Join(root, "bad", "SKILL.md"), "---\nname: broken\n# missing closing frontmatter\n")
    mustWriteFile(t, filepath.Join(root, "bad", "hooks.json"), `{`)
    mustWriteFile(t, filepath.Join(root, "bad", "scripts", "helper.sh"), "echo hi\n")

    artifacts, err := Discover(root)
    if err != nil {
        t.Fatal(err)
    }
    if len(artifacts) != 3 {
        t.Fatalf("expected 3 artifacts, got %d", len(artifacts))
    }

    if artifacts[0].ParseError == "" {
        t.Fatal("expected parse error for malformed hooks.json")
    }
    if artifacts[1].ParseError == "" {
        t.Fatal("expected parse error for malformed SKILL.md")
    }
    if artifacts[2].ParseError != "" {
        t.Fatalf("did not expect parse error for shell script, got %q", artifacts[2].ParseError)
    }
}

func mustWriteFile(t *testing.T, path, content string) {
    t.Helper()
    if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
        t.Fatal(err)
    }
    if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
        t.Fatal(err)
    }
}
