package storage

import (
	"time"

	"github.com/hootmeow/Vuln-Strix/internal/models"
)

// Store defines the methods required for the persistence layer.
type Store interface {
	// Close closes the database connection.
	Close() error

	// AutoMigrate runs the database migrations.
	AutoMigrate() error

	// UpsertHost creates or updates a host.
	UpsertHost(host *models.Host) error
	UpdateHostCriticality(id uint, criticality string) error

	// UpsertVulnerability creates or updates a vulnerability definition.
	UpsertVulnerability(vuln *models.Vulnerability) error

	// FindFindingByFingerprint retrieves a finding by its unique fingerprint.
	FindFindingByFingerprint(fingerprint string) (*models.Finding, error)

	// CreateFinding inserts a new finding.
	CreateFinding(finding *models.Finding) error

	// UpdateFinding updates an existing finding.
	UpdateFinding(finding *models.Finding) error

	// MarkMissingFindingsAsFixed marks findings as fixed if they were seen on a host before but not in the current scan.
	// This logic requires careful implementation in the service layer, but the store needs to support querying.
	// For now, we'll expose a general query or update method.

	// GetFindingsForHost retrieves all findings for a specific host.
	GetFindingsForHost(hostID uint) ([]models.Finding, error)

	// MarkFindingsResolved marks findings as fixed if they were seen on a host before but not in the current scan.
	MarkFindingsResolved(hostID uint, scanTime time.Time) error

	// Dashboard Queries
	GetHostCount() (int64, error)
	GetVulnCount(severity string) (int64, error)
	GetFindingCountByStatus(status string) (int64, error)
	GetHosts() ([]models.Host, error)
	GetHost(id uint) (*models.Host, error)
	GetVulnerabilities() ([]models.Vulnerability, error)

	// Scan Operations
	CreateScan(scan *models.Scan) error
	UpdateScan(scan *models.Scan) error
	AddHostToScan(hostID, scanID uint) error
	GetScans() ([]models.Scan, error)
	GetScan(id uint) (*models.Scan, error)

	// Analytics
	GetAgingStats() (map[string]int, error)
	GetMTTRStats(days int) (map[string]float64, error)
	GetSLACompliance() ([]models.Finding, error)
	GetGhostHosts(days int) ([]models.Host, error)
	GetZombieFindings() ([]models.Finding, error)
	GetAgingCohorts() (map[string]int64, error)
	GetCriticalFindings() ([]models.Finding, error)

	// Admin
	ResetDB() error
	GetSettings() (map[string]string, error)
	UpdateSetting(key, value string) error
	GetSLAConfig() map[string]int
	CreateAuditLog(entry *models.AuditLog) error
	GetAuditLogs(limit int) ([]models.AuditLog, error)

	// Batch 3 Features
	AddHostTag(hostID uint, tag string, color string) error
	RemoveHostTag(hostID uint, tagName string) error
	SnoozeFinding(findingID uint, days int, reason string) error
	UpdateRunbook(vulnID uint, url string) error
	GetFixedFindings(days int) ([]FindingSummary, error)
	GetNewFindings(days int) ([]models.Finding, error)
	GetTopRiskyHosts(limit int) ([]HostRiskSummary, error)
	ResolveFinding(findingID uint, note string) error

	// Phase 5 Features
	GetScanDiff(baseScanID, targetScanID uint) (*models.DiffReport, error)
	GetFamilyStats(days int) (map[string]int, error)

	// Phase 6: Data Export
	GetFindingsForExport(hostID uint) ([]models.Finding, error)

	// Asset Grouping (Tags with Categories)
	GetTagsByCategory(category string) ([]models.Tag, error)
	GetAssetGroups() ([]AssetGroup, error)
	GetHostsByTag(tagName string) ([]models.Host, error)
	GetGroupStats(tagName string) (*GroupStats, error)
	GetFindingsByTag(tagName string) ([]models.Finding, error)
	CreateGroup(tag *models.Tag) error
	UpdateGroup(id uint, name, color, icon string) error
	DeleteGroup(id uint) error
	GetGroupByID(id uint) (*models.Tag, error)

	// Compliance Framework
	GetComplianceFrameworks() ([]models.ComplianceFramework, error)
	GetComplianceControls(frameworkID uint) ([]models.ComplianceControl, error)
	GetFrameworkStats(frameworkCode string) (*FrameworkStats, error)
	GetComplianceGaps(frameworkCode string) ([]ComplianceGap, error)
	CreateComplianceMapping(vulnID, controlID uint, source string) error
	GetVulnerabilityMappings(vulnID uint) ([]models.VulnerabilityComplianceMapping, error)

	// Enhanced Search
	GlobalSearch(criteria FilterCriteria, limit int) ([]SearchResult, error)
	SearchHosts(criteria FilterCriteria) ([]models.Host, error)
	SearchFindings(criteria FilterCriteria) ([]models.Finding, error)
	GetSavedFilters() ([]models.SavedFilter, error)
	CreateSavedFilter(filter *models.SavedFilter) error
	AddSearchHistory(query, userID string, resultCount int) error
	GetSearchSuggestions(prefix string, limit int) ([]string, error)

	// Historical Trending
	CreateMetricSnapshot(snapshot *models.MetricSnapshot) error
	GetMetricSnapshots(metricType string, days int) ([]models.MetricSnapshot, error)
	GetVelocityMetrics(periodDays int, count int) ([]VelocityMetric, error)
	GetMTTRTrend(days int) ([]MTTRTrend, error)
	CollectDailySnapshot() error

	// Seed Data
	SeedDefaultGroups() error
	SeedComplianceFrameworks() error

	// Data Cleanup
	ClearCustomGroups() error
	ClearAuditLog() error
	ClearSettings() error
	ClearSavedFilters() error
	ClearSearchHistory() error
}

type FindingSummary struct {
	HostName      string
	VulnName      string
	Severity      string
	FindingStatus string
}

type HostRiskSummary struct {
	HostID        uint
	Hostname      string
	IP            string
	RiskScore     int
	CriticalCount int
	HighCount     int
}

// AssetGroup represents a group of hosts with statistics.
type AssetGroup struct {
	Tag       models.Tag
	HostCount int
	Stats     GroupStats
}

// GroupStats contains vulnerability statistics for a group.
type GroupStats struct {
	TotalHosts    int
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	OpenFindings  int
}

// FrameworkStats contains compliance statistics for a framework.
type FrameworkStats struct {
	TotalControls   int
	MappedControls  int
	ViolatedCount   int
	ComplianceRate  float64
	CriticalGaps    int
	HighGaps        int
}

// ComplianceGap represents a compliance violation.
type ComplianceGap struct {
	Control       models.ComplianceControl
	Vulnerability models.Vulnerability
	AffectedHosts int
	Severity      string
}

// FilterCriteria represents search filter parameters.
type FilterCriteria struct {
	Query      string
	Severity   []string
	Status     []string
	Tags       []string
	Compliance string
	DateFrom   *time.Time
	DateTo     *time.Time
}

// SearchResult represents a unified search result.
type SearchResult struct {
	Type       string      // "host", "finding", "vulnerability"
	ID         uint
	Title      string
	Subtitle   string
	Severity   string
	URL        string
	MatchField string
	Data       interface{}
}

// VelocityMetric represents new vs fixed findings for a time period.
type VelocityMetric struct {
	PeriodStart time.Time
	PeriodEnd   time.Time
	NewCount    int
	FixedCount  int
	NetChange   int
}

// MTTRTrend represents MTTR over time by severity.
type MTTRTrend struct {
	Date     time.Time
	Severity string
	MTTR     float64
}
