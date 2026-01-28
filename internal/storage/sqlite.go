package storage

import (
	"os"
	"path/filepath"
	"sort"
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
		&Setting{},
	)
}

func (s *SQLiteStore) UpsertHost(host *models.Host) error {
	// Simple upsert based on IP. In reality, we might match on more fields.
	// First check if it exists by IP to get the ID.
	var existing models.Host
	result := s.db.Where("ip = ?", host.IP).First(&existing)
	if result.Error == nil {
		host.ID = existing.ID
		// Preservation logic for manually tagged data
		if existing.Hostname != "" && host.Hostname == "" {
			host.Hostname = existing.Hostname
		}
		if existing.OS != "" && host.OS == "" {
			host.OS = existing.OS
		}
		// If existing has a criticality, keep it unless we want to allow scan overrides
		host.Criticality = existing.Criticality
		return s.db.Save(host).Error
	}
	return s.db.Create(host).Error
}

func (s *SQLiteStore) UpsertVulnerability(vuln *models.Vulnerability) error {
	var existing models.Vulnerability
	result := s.db.Where("plugin_id = ?", vuln.PluginID).First(&existing)
	if result.Error == nil {
		vuln.ID = existing.ID
		// Update fields if they changed (Description, Severity, Solution)
		existing.Name = vuln.Name
		existing.Description = vuln.Description
		existing.Solution = vuln.Solution
		existing.Severity = vuln.Severity
		existing.Family = vuln.Family
		return s.db.Save(&existing).Error
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
	if err != nil {
		return nil, err
	}

	// Manual sort by severity: Critical > High > Medium > Low > Info
	severityOrder := map[string]int{
		"Critical": 4,
		"High":     3,
		"Medium":   2,
		"Low":      1,
		"Info":     0,
	}

	sort.Slice(findings, func(i, j int) bool {
		si := severityOrder[findings[i].Vuln.Severity]
		sj := severityOrder[findings[j].Vuln.Severity]
		if si != sj {
			return si > sj
		}
		// Secondary sort by PluginName
		return findings[i].Vuln.Name < findings[j].Vuln.Name
	})

	return findings, nil
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
	// Join with findings to get host count
	// We use a query that selects vulnerabilities and counts unique host IDs in findings where status is Open
	err := s.db.Model(&models.Vulnerability{}).
		Select("vulnerabilities.*, COUNT(DISTINCT findings.host_id) as host_count_calc").
		Joins("left join findings on findings.vuln_id = vulnerabilities.id AND findings.status = 'Open'").
		Group("vulnerabilities.id").
		Find(&vulns).Error

	if err != nil {
		return nil, err
	}

	// GORM doesn't natively map Select(count) to a gorm:"-" field easily without manual slice map,
	// so let's do a quick map or use a result struct.
	// Actually, easier to just run the count in a loop or use a result struct.
	// Let's use a result struct for the raw query.
	type ScanResult struct {
		models.Vulnerability
		HostCountCalc int
	}
	var results []ScanResult
	s.db.Model(&models.Vulnerability{}).
		Select("vulnerabilities.*, COUNT(DISTINCT findings.host_id) as host_count_calc").
		Joins("left join findings on findings.vuln_id = vulnerabilities.id AND findings.status = 'Open'").
		Group("vulnerabilities.id").
		Scan(&results)

	finalVulns := make([]models.Vulnerability, len(results))
	for i, r := range results {
		r.Vulnerability.HostCount = r.HostCountCalc
		finalVulns[i] = r.Vulnerability
	}

	// Manual sort by severity: Critical, High, Medium, Low, Info
	severityOrder := map[string]int{
		"Critical": 4,
		"High":     3,
		"Medium":   2,
		"Low":      1,
		"Info":     0,
	}

	sort.Slice(finalVulns, func(i, j int) bool {
		si := severityOrder[finalVulns[i].Severity]
		sj := severityOrder[finalVulns[j].Severity]
		if si != sj {
			return si > sj
		}
		return finalVulns[i].Name < finalVulns[j].Name
	})

	return finalVulns, nil
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

func (s *SQLiteStore) GetAgingStats() (map[string]int, error) {
	stats := map[string]int{
		"0-30 Days":  0,
		"31-60 Days": 0,
		"61-90 Days": 0,
		"91+ Days":   0,
	}

	var findings []models.Finding
	err := s.db.Where("status = ?", "Open").Find(&findings).Error
	if err != nil {
		return nil, err
	}

	now := time.Now()
	for _, f := range findings {
		days := int(now.Sub(f.FirstSeen).Hours() / 24)
		if days <= 30 {
			stats["0-30 Days"]++
		} else if days <= 60 {
			stats["31-60 Days"]++
		} else if days <= 90 {
			stats["61-90 Days"]++
		} else {
			stats["91+ Days"]++
		}
	}

	return stats, nil
}

func (s *SQLiteStore) GetMTTRStats() (map[string]float64, error) {
	stats := map[string]float64{
		"Critical": 0,
		"High":     0,
		"Medium":   0,
		"Low":      0,
		"Info":     0,
	}
	counts := map[string]int{
		"Critical": 0,
		"High":     0,
		"Medium":   0,
		"Low":      0,
		"Info":     0,
	}

	var findings []models.Finding
	err := s.db.Preload("Vuln").Where("status = ?", "Fixed").Find(&findings).Error
	if err != nil {
		return nil, err
	}

	for _, f := range findings {
		days := f.LastSeen.Sub(f.FirstSeen).Hours() / 24
		stats[f.Vuln.Severity] += days
		counts[f.Vuln.Severity]++
	}

	for sev := range stats {
		if counts[sev] > 0 {
			stats[sev] = stats[sev] / float64(counts[sev])
		}
	}

	return stats, nil
}

func (s *SQLiteStore) GetSLACompliance() ([]models.Finding, error) {
	// Define SLA windows (days)
	sla := map[string]int{
		"Critical": 7,
		"High":     14,
		"Medium":   30,
		"Low":      60,
		"Info":     90,
	}

	var breaches []models.Finding
	var openFindings []models.Finding
	err := s.db.Preload("Vuln").Preload("Host").Where("status = ?", "Open").Find(&openFindings).Error
	if err != nil {
		return nil, err
	}

	now := time.Now()
	for _, f := range openFindings {
		days := int(now.Sub(f.FirstSeen).Hours() / 24)
		if days > sla[f.Vuln.Severity] {
			breaches = append(breaches, f)
		}
	}

	return breaches, nil
}

func (s *SQLiteStore) ResetDB() error {
	// Truncate all tables
	// GORM doesn't have a direct Truncate, so we use raw SQL or Delete all.
	// Delete all is portable.

	// Delete in order to respect foreign keys if enforced (SQLite usually OK with cascade or if not enforced)
	// Findings depends on Host and Vuln. HostScans depends on Host and Scan.

	if err := s.db.Exec("DELETE FROM host_scans").Error; err != nil {
		return err
	}
	if err := s.db.Exec("DELETE FROM findings").Error; err != nil {
		return err
	}
	if err := s.db.Exec("DELETE FROM scans").Error; err != nil {
		return err
	}
	if err := s.db.Exec("DELETE FROM hosts").Error; err != nil {
		return err
	}
	// We might want to keep vulnerabilities if they are global definitions, but for a "hard reset" we clear them too.
	if err := s.db.Exec("DELETE FROM vulnerabilities").Error; err != nil {
		return err
	}

	return nil
}
