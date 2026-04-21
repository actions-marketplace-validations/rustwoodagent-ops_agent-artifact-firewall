package aaf

type ScanOptions struct {
    Path          string
    Format        string
    Out           string
    FailOn        string
    MaxRiskScore  int
    ExitOnFinding bool
}

type Artifact struct {
    Path         string         `json:"path"`
    Type         string         `json:"type"`
    Parser       string         `json:"parser,omitempty"`
    RelativePath string         `json:"relative_path,omitempty"`
    Parsed       map[string]any `json:"parsed,omitempty"`
    ParseError   string         `json:"parse_error,omitempty"`
}

type Finding struct {
    RuleID         string `json:"rule_id"`
    Severity       string `json:"severity"`
    Title          string `json:"title"`
    Path           string `json:"path"`
    Line           int    `json:"line,omitempty"`
    Evidence       string `json:"evidence,omitempty"`
    Explanation    string `json:"explanation"`
    Recommendation string `json:"recommendation"`
    Confidence     string `json:"confidence"`
}

type ScanResult struct {
    Tool      string     `json:"tool"`
    Version   string     `json:"version"`
    Target    string     `json:"target"`
    Decision  string     `json:"decision"`
    RiskScore int        `json:"risk_score"`
    Artifacts []Artifact `json:"artifacts"`
    Findings  []Finding  `json:"findings"`
}
