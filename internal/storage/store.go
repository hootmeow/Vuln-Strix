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
	GetHosts() ([]models.Host, error)
	GetHost(id uint) (*models.Host, error)
	GetVulnerabilities() ([]models.Vulnerability, error)

	// Scan Operations
	CreateScan(scan *models.Scan) error
	UpdateScan(scan *models.Scan) error
	AddHostToScan(hostID, scanID uint) error
	GetScans() ([]models.Scan, error)
	GetScan(id uint) (*models.Scan, error)
}
