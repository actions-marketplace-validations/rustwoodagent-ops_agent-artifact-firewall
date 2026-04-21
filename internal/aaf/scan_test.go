package aaf

import "testing"

func TestMaliciousFixtureBlocks(t *testing.T) { result, err := Scan(ScanOptions{Path: "../../examples/malicious-skill", MaxRiskScore:70}); if err != nil { t.Fatal(err) }; if result.Decision != "block" { t.Fatalf("expected block, got %s", result.Decision) }; if result.RiskScore < 70 { t.Fatalf("expected score >= 70, got %d", result.RiskScore) }; if len(result.Findings)==0 { t.Fatal("expected findings") } }
func TestSafeFixtureAllows(t *testing.T) { result, err := Scan(ScanOptions{Path: "../../examples/safe-skill", MaxRiskScore:70}); if err != nil { t.Fatal(err) }; if result.Decision != "allow" { t.Fatalf("expected allow, got %s", result.Decision) } }
func TestRenderJSON(t *testing.T) { result, err := Scan(ScanOptions{Path: "../../examples/safe-skill"}); if err != nil { t.Fatal(err) }; out, err := Render(result, "json"); if err != nil { t.Fatal(err) }; if out == "" || out[0] != '{' { t.Fatal("expected JSON object") } }
