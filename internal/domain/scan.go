package domain

import "time"

const (
	StatusClean     = "clean"
	StatusMalicious = "malicious"
	StatusError     = "error"
	StatusSkipped   = "skipped"
)

const (
	ScopeURL  = "url"
	ScopeFile = "file"
)

type Job struct {
	ID          string                 `json:"id"`
	Status      string                 `json:"status"`
	Scope       string                 `json:"scope"`
	SubmittedAt time.Time              `json:"submitted_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Result      ScanResult             `json:"result"`
	Events      []ScanEvent            `json:"events"`
	Metadata    map[string]string      `json:"metadata,omitempty"`
}

type ScanEvent struct {
	Timestamp time.Time              `json:"timestamp"`
	Status    string                 `json:"status"`
	Engine    string                 `json:"engine"`
	Message   string                 `json:"message"`
	Details   map[string]any         `json:"details,omitempty"`
}

type ScanResult struct {
	Status        string                 `json:"status"`
	Scope         string                 `json:"scope"`
	PrimaryEngine string                 `json:"primary_engine"`
	CheckedAt     time.Time              `json:"checked_at"`
	Quarantined   bool                   `json:"quarantined"`
	Escalation    bool                   `json:"escalation"`
	ReasonCode    string                 `json:"reason_code"`
	Reason        string                 `json:"reason"`
	Details       map[string]any         `json:"details,omitempty"`
}

type URLScanRequest struct {
	URL string `json:"url"`
}
