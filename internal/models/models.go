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

// TagCategory represents the type of tag for grouping purposes.
type TagCategory string

const (
	TagCategoryGeneral      TagCategory = "General"
	TagCategoryBusinessUnit TagCategory = "BusinessUnit"
	TagCategoryEnvironment  TagCategory = "Environment"
	TagCategoryNetwork      TagCategory = "Network"
)

// Tag represents a label applied to a host.
type Tag struct {
	gorm.Model
	Name     string      `gorm:"uniqueIndex:idx_tag_name_cat" json:"name"`
	Color    string      `json:"color"`
	Category TagCategory `gorm:"size:50;default:'General';uniqueIndex:idx_tag_name_cat" json:"category"`
	Icon     string      `gorm:"size:50" json:"icon"`
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
	CVEs        string  `json:"cves"`       // Comma-separated or JSON
	Compliance  string  `json:"compliance"` // e.g. "PCI-DSS v3.2, NIST 800-53"

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

// AgeDays returns the number of days since the finding was first seen
func (f Finding) AgeDays() int {
	return int(time.Since(f.FirstSeen).Hours() / 24)
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

// AuditLog tracks critical actions taken in the system.
type AuditLog struct {
	gorm.Model
	User      string `json:"user"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Details   string `json:"details"`
	IPAddress string `json:"ip_address"`
}

// ComplianceFramework represents a compliance standard (PCI-DSS, HIPAA, etc.)
type ComplianceFramework struct {
	gorm.Model
	Code        string `gorm:"uniqueIndex;size:50" json:"code"`
	Name        string `gorm:"size:255" json:"name"`
	Version     string `gorm:"size:50" json:"version"`
	Description string `json:"description"`
	Color       string `gorm:"size:20" json:"color"`
}

// ComplianceControl represents a specific control within a framework.
type ComplianceControl struct {
	gorm.Model
	FrameworkID uint                `gorm:"index" json:"framework_id"`
	Framework   ComplianceFramework `json:"framework"`
	ControlID   string              `gorm:"size:50;index" json:"control_id"`
	Title       string              `gorm:"size:255" json:"title"`
	Description string              `json:"description"`
	Priority    int                 `json:"priority"`
}

// VulnerabilityComplianceMapping maps vulnerabilities to compliance controls.
type VulnerabilityComplianceMapping struct {
	gorm.Model
	VulnerabilityID uint              `gorm:"index" json:"vulnerability_id"`
	ControlID       uint              `gorm:"index" json:"control_id"`
	Control         ComplianceControl `json:"control"`
	MappingSource   string            `gorm:"size:50" json:"mapping_source"`
}

// SavedFilter represents a saved search filter preset.
type SavedFilter struct {
	gorm.Model
	Name        string `gorm:"size:100" json:"name"`
	Description string `json:"description"`
	FilterJSON  string `json:"filter_json"`
	EntityType  string `gorm:"size:50" json:"entity_type"`
	IsGlobal    bool   `gorm:"default:true" json:"is_global"`
	UsageCount  int    `gorm:"default:0" json:"usage_count"`
}

// SearchHistory tracks search queries for suggestions and analytics.
type SearchHistory struct {
	gorm.Model
	Query       string `gorm:"size:255" json:"query"`
	UserID      string `gorm:"size:100;index" json:"user_id"`
	ResultCount int    `json:"result_count"`
}

// MetricSnapshot captures point-in-time metrics for trending analysis.
type MetricSnapshot struct {
	gorm.Model
	SnapshotDate time.Time `gorm:"index" json:"snapshot_date"`
	MetricType   string    `gorm:"size:50;index" json:"metric_type"`
	Dimension    string    `gorm:"size:100" json:"dimension"`
	Value        float64   `json:"value"`
	Metadata     string    `json:"metadata"`
}
