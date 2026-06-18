package sarif

// Minimal SARIF 2.1.0 types — only the fields needed to emit findings that GitHub
// code scanning and other SARIF consumers accept. See the SARIF 2.1.0 spec for the
// full schema.

// Log is the root SARIF object.
type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run is a single tool run.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool wraps the analysis tool's driver.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver describes the analysis tool and its rules.
type Driver struct {
	Name           string                `json:"name"`
	Version        string                `json:"version,omitempty"`
	InformationURI string                `json:"informationUri,omitempty"`
	Rules          []ReportingDescriptor `json:"rules,omitempty"`
}

// ReportingDescriptor is a rule definition.
type ReportingDescriptor struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription Message        `json:"shortDescription,omitempty"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

// Result is a single finding instance.
type Result struct {
	RuleID     string         `json:"ruleId"`
	RuleIndex  int            `json:"ruleIndex"`
	Level      string         `json:"level"`
	Message    Message        `json:"message"`
	Locations  []Location     `json:"locations,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Message holds human-readable text.
type Message struct {
	Text string `json:"text"`
}

// Location points at where a result was found.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation wraps an artifact location.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
}

// ArtifactLocation is a URI (a host or URL for network findings).
type ArtifactLocation struct {
	URI string `json:"uri"`
}
