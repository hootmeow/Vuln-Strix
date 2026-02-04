package models

import (
	"time"

	"gorm.io/gorm"
)

// Host represents a unique asset in the environment.
type Host struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	IP          string `gorm:"uniqueIndex;size:50" json:"ip"` // Support IPv6
	Hostname    string `gorm:"size:255" json:"hostname"`
	OS          string `gorm:"size:255" json:"os"`
	Criticality string `gorm:"size:20;default:'Medium'" json:"criticality"` // High, Medium, Low

	Tags  []Tag  `gorm:"many2many:host_tags;" json:"tags"`
	Scans []Scan `gorm:"many2many:host_scans;" json:"scans,omitempty"`
}

// Scan represents a single imported Nessus scan file.
type Scan struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name       string    `gorm:"size:255" json:"name"`
	PolicyName string    `gorm:"size:255" json:"policy_name"`
	PluginSet  string    `gorm:"size:50" json:"plugin_set"`
	ScanStart  time.Time `json:"scan_start"`
	ScanEnd    time.Time `json:"scan_end"`

	// Imported Stats (Snapshot at time of import)
	CriticalCount int `json:"critical_count"`
	HighCount     int `json:"high_count"`
	MediumCount   int `json:"medium_count"`
	LowCount      int `json:"low_count"`
}

// Tag represents a label applied to a host.
type Tag struct {
	gorm.Model
	Name  string `gorm:"uniqueIndex" json:"name"`
	Color string `json:"color"`
}

// Vulnerability represents a definition of a security issue (e.g., a Nessus Plugin).
type Vulnerability struct {
	gorm.Model
	PluginID    string  `gorm:"uniqueIndex" json:"plugin_id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Solution    string  `json:"solution"`
	Severity    string  `json:"severity"` // Critical, High, Medium, Low, Info
	CVSS        float64 `json:"cvss"`
	Family      string  `json:"family"`
	CVEs        string  `json:"cves"` // Comma-separated or JSON

	// Enrichment
	RunbookURL string `json:"runbook_url"`
	InKEV      bool   `json:"in_kev"` // CISA Known Exploited

	HostCount int `gorm:"-" json:"host_count"` // Not persisted
}

// Finding represents the state of a vulnerability on a specific host.
type Finding struct {
	gorm.Model
	HostID          uint          `gorm:"index" json:"host_id"`
	Host            Host          `json:"host"`
	VulnerabilityID uint          `gorm:"index" json:"vulnerability_id"`
	Vuln            Vulnerability `gorm:"foreignKey:VulnerabilityID" json:"vuln"`
	ScanID          uint          `gorm:"index" json:"scan_id"`
	Port            int           `json:"port"`
	Protocol        string        `json:"protocol"`
	FirstSeen       time.Time     `json:"first_seen"`
	LastSeen        time.Time     `json:"last_seen"`
	Fingerprint     string        `gorm:"uniqueIndex" json:"fingerprint"`
	Status          string        `gorm:"size:50;index" json:"status"` // Open, Fixed, Risk Accepted
	ReopenCount     int           `gorm:"default:0" json:"reopen_count"`
	FixedAt         time.Time     `json:"fixed_at"`

	// Exception Workflow
	SnoozedUntil    *time.Time `json:"snoozed_until"`
	ExceptionReason string     `json:"exception_reason"`

	// Manual Resolution
	ResolutionNote string `json:"resolution_note"`
}

// DiffReport represents the comparison between two scans or timeframes.
type DiffReport struct {
	BaseScanID   uint      `json:"base_scan_id"`
	TargetScanID uint      `json:"target_scan_id"`
	New          []Finding `json:"new"`
	Fixed        []Finding `json:"fixed"`
	Regressed    []Finding `json:"regressed"`
	Stats        struct {
		NewCount       int `json:"new_count"`
		FixedCount     int `json:"fixed_count"`
		RegressedCount int `json:"regressed_count"`
	} `json:"stats"`
}
