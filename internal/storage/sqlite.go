package storage

import (
	"log"
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
		Logger: logger.Default.LogMode(logger.Error),
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
		&models.Tag{},
		&Setting{},
		&models.AuditLog{},
		&models.ComplianceFramework{},
		&models.ComplianceControl{},
		&models.VulnerabilityComplianceMapping{},
		&models.SavedFilter{},
		&models.SearchHistory{},
		&models.MetricSnapshot{},
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
	// These are findings that were NOT seen in the current scan, indicating they've been remediated
	now := time.Now()
	result := s.db.Model(&models.Finding{}).
		Where("host_id = ? AND status = ? AND last_seen < ?", hostID, "Open", scanTime).
		Updates(map[string]interface{}{
			"status":     "Fixed",
			"fixed_at":   now,
			"updated_at": now,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected > 0 {
		// Log remediation detection for debugging
		var host models.Host
		s.db.First(&host, hostID)
		log.Printf("Remediation detected: %d findings marked as Fixed for host %s", result.RowsAffected, host.IP)
	}
	return nil
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
		Joins("join vulnerabilities on vulnerabilities.id = findings.vulnerability_id").
		Where("vulnerabilities.severity = ? AND findings.status = ?", severity, "Open").
		Count(&count).Error
	log.Printf("GetVulnCount(%s): count=%d, err=%v", severity, count, err)
	return count, err
}

func (s *SQLiteStore) GetFindingCountByStatus(status string) (int64, error) {
	var count int64
	err := s.db.Model(&models.Finding{}).Where("status = ?", status).Count(&count).Error
	return count, err
}

func (s *SQLiteStore) GetHosts() ([]models.Host, error) {
	var hosts []models.Host
	err := s.db.Model(&models.Host{}).Order("updated_at desc").Find(&hosts).Error
	return hosts, err
}

func (s *SQLiteStore) GetHost(id uint) (*models.Host, error) {
	var host models.Host
	err := s.db.Preload("Scans").Preload("Tags").First(&host, id).Error
	if err != nil {
		return nil, err
	}
	return &host, nil
}

func (s *SQLiteStore) UpdateHostCriticality(id uint, criticality string) error {
	return s.db.Model(&models.Host{}).Where("id = ?", id).Update("criticality", criticality).Error
}

func (s *SQLiteStore) CreateAuditLog(entry *models.AuditLog) error {
	return s.db.Create(entry).Error
}

func (s *SQLiteStore) GetAuditLogs(limit int) ([]models.AuditLog, error) {
	var logs []models.AuditLog
	err := s.db.Order("created_at desc").Limit(limit).Find(&logs).Error
	return logs, err
}

func (s *SQLiteStore) GetVulnerabilities() ([]models.Vulnerability, error) {
	// Join with findings to get host count
	// We use a query that selects vulnerabilities and counts unique host IDs in findings where status is Open
	// Fix: Column name is vulnerability_id, not vuln_id
	type ScanResult struct {
		models.Vulnerability
		HostCountCalc int
	}
	var results []ScanResult

	err := s.db.Model(&models.Vulnerability{}).
		Select("vulnerabilities.*, COUNT(DISTINCT findings.host_id) as host_count_calc").
		Joins("left join findings on findings.vulnerability_id = vulnerabilities.id AND findings.status = 'Open'").
		Group("vulnerabilities.id").
		Scan(&results).Error

	if err != nil {
		return nil, err
	}

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

func (s *SQLiteStore) GetMTTRStats(days int) (map[string]float64, error) {
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

	since := time.Now().AddDate(0, 0, -days)
	var findings []models.Finding
	// Query findings fixed within the specified time window using fixed_at timestamp
	err := s.db.Preload("Vuln").Where("status = ? AND fixed_at >= ?", "Fixed", since).Find(&findings).Error
	if err != nil {
		return nil, err
	}

	for _, f := range findings {
		// MTTR = time from first detection to fix confirmation
		mttrDays := f.FixedAt.Sub(f.FirstSeen).Hours() / 24
		stats[f.Vuln.Severity] += mttrDays
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

// ClearCustomGroups deletes all custom tags/groups (including host associations)
func (s *SQLiteStore) ClearCustomGroups() error {
	// First remove all host-tag associations
	if err := s.db.Exec("DELETE FROM host_tags").Error; err != nil {
		return err
	}
	// Then delete all tags
	if err := s.db.Exec("DELETE FROM tags").Error; err != nil {
		return err
	}
	return nil
}

// ClearAuditLog deletes all audit log entries
func (s *SQLiteStore) ClearAuditLog() error {
	return s.db.Exec("DELETE FROM audit_logs").Error
}

// ClearSettings resets all settings to defaults by deleting them
func (s *SQLiteStore) ClearSettings() error {
	return s.db.Exec("DELETE FROM settings").Error
}

// ClearSavedFilters deletes all saved search filters
func (s *SQLiteStore) ClearSavedFilters() error {
	return s.db.Exec("DELETE FROM saved_filters").Error
}

// ClearSearchHistory deletes all search history
func (s *SQLiteStore) ClearSearchHistory() error {
	return s.db.Exec("DELETE FROM search_histories").Error
}

func (s *SQLiteStore) GetGhostHosts(days int) ([]models.Host, error) {
	var hosts []models.Host
	cutoff := time.Now().AddDate(0, 0, -days)
	err := s.db.Where("updated_at < ?", cutoff).Find(&hosts).Error
	return hosts, err
}

func (s *SQLiteStore) GetZombieFindings() ([]models.Finding, error) {
	var findings []models.Finding
	err := s.db.Preload("Vuln").Preload("Host").Where("reopen_count > 0 AND status = ?", "Open").Find(&findings).Error
	return findings, err
}

func (s *SQLiteStore) GetAgingCohorts() (map[string]int64, error) {
	cohorts := make(map[string]int64)

	// Buckets: <30, 30-60, 60-90, 90+
	var findings []models.Finding
	if err := s.db.Where("status = ?", "Open").Find(&findings).Error; err != nil {
		return nil, err
	}

	now := time.Now()
	for _, f := range findings {
		days := int(now.Sub(f.FirstSeen).Hours() / 24)
		if days < 30 {
			cohorts["Fresh (<30d)"]++
		} else if days < 60 {
			cohorts["Aging (30-60d)"]++
		} else if days < 90 {
			cohorts["Stale (60-90d)"]++
		} else {
			cohorts["Legacy (90d+)"]++
		}
	}
	return cohorts, nil
}

// GetFixedFindings returns findings that have been verified Fixed recently.
// Uses fixed_at timestamp to identify when the finding was remediated.
func (s *SQLiteStore) GetFixedFindings(days int) ([]FindingSummary, error) {
	var findings []models.Finding
	since := time.Now().AddDate(0, 0, -days)

	// Query findings that were marked Fixed within the specified time window
	if err := s.db.Preload("Vuln").Preload("Host").
		Where("status = ? AND fixed_at > ?", "Fixed", since).
		Find(&findings).Error; err != nil {
		return nil, err
	}

	var summaries []FindingSummary
	for _, f := range findings {
		summaries = append(summaries, FindingSummary{
			HostName:      f.Host.Hostname,
			VulnName:      f.Vuln.Name,
			Severity:      f.Vuln.Severity,
			FindingStatus: f.Status,
		})
	}
	return summaries, nil
}

func (s *SQLiteStore) GetCriticalFindings() ([]models.Finding, error) {
	var findings []models.Finding
	// Find findings where status is Open and associated Vuln severity is Critical
	// We need to join.
	// GORM Syntax: Joins("Vuln").Where("Vuln.severity = ?", "Critical") (if Vuln is association, explicit join might be needed for where clause if not using Preload with conditional)
	// Safest GORM way for filtering on association:
	err := s.db.Joins("Vuln").Preload("Host").Where("Vuln.severity = ? AND findings.status = ?", "Critical", "Open").Find(&findings).Error
	return findings, err
}

// GetNewFindings returns findings that were first seen within the last N days (status Open)
func (s *SQLiteStore) GetNewFindings(days int) ([]models.Finding, error) {
	var findings []models.Finding
	since := time.Now().AddDate(0, 0, -days)
	// We want findings that are Open and FirstSeen is recent.
	err := s.db.Preload("Vuln").Preload("Host").
		Where("status = ? AND first_seen >= ?", "Open", since).
		Order("vulnerability_id asc").
		Find(&findings).Error
	return findings, err
}

// GetTopRiskyHosts calculates a risk score for each host and returns the top N.
// Risk Score = (Critical * 10) + (High * 5) + (Medium * 1)
func (s *SQLiteStore) GetTopRiskyHosts(limit int) ([]HostRiskSummary, error) {
	var results []HostRiskSummary
	err := s.db.Table("findings").
		Select("hosts.id as host_id, hosts.hostname, hosts.ip, "+
			"SUM(CASE WHEN vulnerabilities.severity = 'Critical' THEN 10 WHEN vulnerabilities.severity = 'High' THEN 5 WHEN vulnerabilities.severity = 'Medium' THEN 1 ELSE 0 END) as risk_score, "+
			"SUM(CASE WHEN vulnerabilities.severity = 'Critical' THEN 1 ELSE 0 END) as critical_count, "+
			"SUM(CASE WHEN vulnerabilities.severity = 'High' THEN 1 ELSE 0 END) as high_count").
		Joins("JOIN vulnerabilities ON vulnerabilities.id = findings.vulnerability_id").
		Joins("JOIN hosts ON hosts.id = findings.host_id").
		Where("findings.status = ?", "Open").
		Group("hosts.id, hosts.hostname, hosts.ip").
		Order("risk_score DESC").
		Limit(limit).
		Scan(&results).Error

	return results, err
}

func (s *SQLiteStore) ResolveFinding(findingID uint, note string) error {
	return s.db.Model(&models.Finding{}).Where("id = ?", findingID).
		Updates(map[string]interface{}{
			"status":          "Fixed",
			"resolution_note": note,
			"fixed_at":        time.Now(),
		}).Error
}
