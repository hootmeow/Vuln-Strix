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

// Vulnerability represents a definition of a security issue (e.g., a Nessus Plugin).
type Vulnerability struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	PluginID    string `gorm:"uniqueIndex;size:100" json:"plugin_id"` // String to support potential non-numeric IDs from other scanners later
	Name        string `gorm:"size:255" json:"name"`
	Description string `gorm:"type:text" json:"description"`
	Solution    string `gorm:"type:text" json:"solution"`
	Severity    string `gorm:"size:50" json:"severity"` // Critical, High, Medium, Low, Info
	Family      string `gorm:"size:100" json:"family"`
	HostCount   int    `gorm:"-" json:"host_count"` // Not persisted, calculated on demand
}

// Finding represents the state of a vulnerability on a specific host.
type Finding struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	HostID uint `gorm:"index" json:"host_id"`
	Host   Host `gorm:"foreignKey:HostID" json:"host,omitempty"`

	VulnID uint          `gorm:"index" json:"vuln_id"`
	Vuln   Vulnerability `gorm:"foreignKey:VulnID" json:"vuln,omitempty"`

	Port     int    `json:"port"`
	Protocol string `gorm:"size:20" json:"protocol"`

	// Fingerprint is the SHA256 hash of TargetIP + PluginID + Port + Protocol
	Fingerprint string `gorm:"uniqueIndex;size:64" json:"fingerprint"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	Status string `gorm:"size:50;index" json:"status"` // Open, Fixed, Risk Accepted
}
