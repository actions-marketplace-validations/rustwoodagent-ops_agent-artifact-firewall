package main

import (
    "fmt"
    "os"
    "strconv"

    "github.com/rustwoodagent-ops/agent-artifact-firewall/internal/aaf"
)

const version = "0.1.0-dev"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
    if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
        printHelp()
        return 0
    }
    switch args[0] {
    case "version", "--version", "-v":
        fmt.Println("AGENT-ARTIFACT-FIREWALL", version)
        return 0
    case "scan":
        return scan(args[1:])
    default:
        fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", args[0])
        printHelp()
        return 2
    }
}

func scan(args []string) int {
    opts := aaf.ScanOptions{Path: ".", Format: "text", FailOn: "high", MaxRiskScore: 70, ExitOnFinding: true}
    if len(args) > 0 && args[0] != "--format" && args[0] != "--out" && args[0] != "--fail-on" && args[0] != "--max-risk-score" && args[0] != "--no-fail" {
        opts.Path = args[0]
        args = args[1:]
    }
    for i := 0; i < len(args); i++ {
        switch args[i] {
        case "--format":
            i++
            if i >= len(args) { fmt.Fprintln(os.Stderr, "--format requires a value"); return 2 }
            opts.Format = args[i]
        case "--out":
            i++
            if i >= len(args) { fmt.Fprintln(os.Stderr, "--out requires a value"); return 2 }
            opts.Out = args[i]
        case "--fail-on":
            i++
            if i >= len(args) { fmt.Fprintln(os.Stderr, "--fail-on requires a value"); return 2 }
            opts.FailOn = args[i]
        case "--max-risk-score":
            i++
            if i >= len(args) { fmt.Fprintln(os.Stderr, "--max-risk-score requires a number"); return 2 }
            n, err := strconv.Atoi(args[i]); if err != nil { fmt.Fprintf(os.Stderr, "invalid score: %v\n", err); return 2 }
            opts.MaxRiskScore = n
        case "--no-fail":
            opts.ExitOnFinding = false
        default:
            fmt.Fprintf(os.Stderr, "unknown option: %s\n", args[i])
            return 2
        }
    }
    result, err := aaf.Scan(opts)
    if err != nil { fmt.Fprintf(os.Stderr, "scan failed: %v\n", err); return 1 }
    rendered, err := aaf.Render(result, opts.Format)
    if err != nil { fmt.Fprintf(os.Stderr, "render failed: %v\n", err); return 1 }
    if opts.Out != "" {
        if err := os.WriteFile(opts.Out, []byte(rendered), 0644); err != nil { fmt.Fprintf(os.Stderr, "write output failed: %v\n", err); return 1 }
    } else {
        fmt.Print(rendered)
        if len(rendered) == 0 || rendered[len(rendered)-1] != '\n' { fmt.Println() }
    }
    if opts.ExitOnFinding && aaf.ShouldFail(result, opts.FailOn, opts.MaxRiskScore) { return 1 }
    return 0
}

func printHelp() {
    fmt.Println(`AGENT-ARTIFACT-FIREWALL

Usage:
  aaf scan <path> [--format text|json|sarif|markdown] [--out file] [--fail-on low|medium|high|critical|none]
  aaf version`)
}
