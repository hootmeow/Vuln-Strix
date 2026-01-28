package storage

import (
	"os"
	"path/filepath"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/hootmeow/Vuln-Strix/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type SQLiteStore struct {
	db *gorm.DB
}

// NewSQLiteStore initializes a new SQLite database connection.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, err
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, err
	}

	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (s *SQLiteStore) AutoMigrate() error {
	return s.db.AutoMigrate(
		&models.Host{},
		&models.Vulnerability{},
		&models.Finding{},
		&models.Scan{},
	)
}

func (s *SQLiteStore) UpsertHost(host *models.Host) error {
	// Simple upsert based on IP. In reality, we might match on more fields.
	// First check if it exists by IP to get the ID.
	var existing models.Host
	result := s.db.Where("ip = ?", host.IP).First(&existing)
	if result.Error == nil {
		host.ID = existing.ID
		// Update fields if needed, or just touch UpdatedAt
		return s.db.Save(host).Error
	}
	return s.db.Create(host).Error
}

func (s *SQLiteStore) UpsertVulnerability(vuln *models.Vulnerability) error {
	var existing models.Vulnerability
	result := s.db.Where("plugin_id = ?", vuln.PluginID).First(&existing)
	if result.Error == nil {
		vuln.ID = existing.ID
		return s.db.Save(vuln).Error
	}
	return s.db.Create(vuln).Error
}

func (s *SQLiteStore) FindFindingByFingerprint(fingerprint string) (*models.Finding, error) {
	var finding models.Finding
	err := s.db.Where("fingerprint = ?", fingerprint).First(&finding).Error
	if err != nil {
		return nil, err
	}
	return &finding, nil
}

func (s *SQLiteStore) CreateFinding(finding *models.Finding) error {
	return s.db.Create(finding).Error
}

func (s *SQLiteStore) UpdateFinding(finding *models.Finding) error {
	return s.db.Save(finding).Error
}

func (s *SQLiteStore) GetFindingsForHost(hostID uint) ([]models.Finding, error) {
	var findings []models.Finding
	err := s.db.Preload("Vuln").Where("host_id = ?", hostID).Find(&findings).Error
	return findings, err
}

func (s *SQLiteStore) MarkFindingsResolved(hostID uint, scanTime time.Time) error {
	// Update findings for this host that are currently Open, but their LastSeen is before the scanTime
	return s.db.Model(&models.Finding{}).
		Where("host_id = ? AND status = ? AND last_seen < ?", hostID, "Open", scanTime).
		Updates(map[string]interface{}{
			"status":     "Fixed",
			"updated_at": time.Now(),
		}).Error
}

func (s *SQLiteStore) GetHostCount() (int64, error) {
	var count int64
	err := s.db.Model(&models.Host{}).Count(&count).Error
	return count, err
}

func (s *SQLiteStore) GetVulnCount(severity string) (int64, error) {
	var count int64
	// We need to join finding -> vuln to query by severity
	err := s.db.Model(&models.Finding{}).
		Joins("join vulnerabilities on vulnerabilities.id = findings.vuln_id").
		Where("vulnerabilities.severity = ? AND findings.status = ?", severity, "Open").
		Count(&count).Error
	return count, err
}

func (s *SQLiteStore) GetHosts() ([]models.Host, error) {
	var hosts []models.Host
	err := s.db.Model(&models.Host{}).Order("updated_at desc").Find(&hosts).Error
	return hosts, err
}

func (s *SQLiteStore) GetHost(id uint) (*models.Host, error) {
	var host models.Host
	err := s.db.Preload("Scans").First(&host, id).Error
	if err != nil {
		return nil, err
	}
	return &host, nil
}

func (s *SQLiteStore) GetVulnerabilities() ([]models.Vulnerability, error) {
	var vulns []models.Vulnerability
	err := s.db.Order("severity desc, name asc").Find(&vulns).Error
	return vulns, err
}

func (s *SQLiteStore) CreateScan(scan *models.Scan) error {
	return s.db.Create(scan).Error
}

func (s *SQLiteStore) UpdateScan(scan *models.Scan) error {
	return s.db.Save(scan).Error
}

func (s *SQLiteStore) AddHostToScan(hostID, scanID uint) error {
	// GORM many2many association
	host := models.Host{ID: hostID}
	scan := models.Scan{ID: scanID}
	return s.db.Model(&host).Association("Scans").Append(&scan)
}

func (s *SQLiteStore) GetScans() ([]models.Scan, error) {
	var scans []models.Scan
	err := s.db.Order("scan_start desc").Find(&scans).Error
	return scans, err
}

func (s *SQLiteStore) GetScan(id uint) (*models.Scan, error) {
	var scan models.Scan
	err := s.db.First(&scan, id).Error
	if err != nil {
		return nil, err
	}
	return &scan, nil
}
