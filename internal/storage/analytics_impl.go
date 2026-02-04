package storage

import (
	"time"

	"github.com/hootmeow/Vuln-Strix/internal/models"
)

// GetScanDiff compares two scans to find new, fixed, and regressed findings.
// Since our findings model is mutable (updates in place), we use heuristics based on timestamps.
// New: FirstSeen ~= TargetScan.ScanStart
// Fixed: Status=Fixed AND FixedAt >= BaseScan.ScanStart (or LastSeen)
// Regressed: Status=Open AND ReopenCount > 0
func (s *SQLiteStore) GetScanDiff(baseScanID, targetScanID uint) (*models.DiffReport, error) {
	report := &models.DiffReport{
		BaseScanID:   baseScanID,
		TargetScanID: targetScanID,
		New:          []models.Finding{},
		Fixed:        []models.Finding{},
		Regressed:    []models.Finding{},
	}

	// 1. Get Target Scan to know the timeframe
	var targetScan models.Scan
	if err := s.db.First(&targetScan, targetScanID).Error; err != nil {
		return nil, err
	}

	// 2. Identify "New" Findings
	// Findings where FirstSeen is close to the TargetScan start time (within a margin, say 1 hour or just >= ScanStart)
	// AND ScanID matches target (meaning it was seen in this scan)
	if err := s.db.Preload("Vuln").Preload("Host").
		Where("scan_id = ? AND first_seen >= ?", targetScanID, targetScan.ScanStart.Add(-1*time.Hour)).
		Find(&report.New).Error; err != nil {
		return nil, err
	}
	report.Stats.NewCount = len(report.New)

	// 3. Identify "Fixed" Findings
	// Findings that are marked Fixed
	// We might restrict this to fixes *since* the base scan if we had a reliable base time.
	// For "Scan Diff", we usually mean "What was fixed *by* this scan compared to the last one?"
	// So we look for findings where FixedAt is roughly now (ScanEnd)
	// Or simply: Status=Fixed.
	// For accurate diffs, we'd need a "ScanEvents" table.
	// Heuristic: Fixed within the last 24h of the scan import?
	// Let's assume the user runs this diff shortly after scanning.
	// Better: Findings where LastSeen was BEFORE TargetScan, but aren't seen in TargetScan?
	// Actually, logic is: "Was Open, Now Fixed".
	// Let's query recent fixes.
	if err := s.db.Preload("Vuln").Preload("Host").
		Where("status = ? AND fixed_at >= ?", "Fixed", targetScan.ScanStart.Add(-24*time.Hour)).
		Find(&report.Fixed).Error; err != nil {
		return nil, err
	}
	report.Stats.FixedCount = len(report.Fixed)

	// 4. Identify "Regressed" Findings
	// Status=Open, ReopenCount > 0, Seen in Target Scan
	if err := s.db.Preload("Vuln").Preload("Host").
		Where("scan_id = ? AND status = ? AND reopen_count > 0", targetScanID, "Open").
		Find(&report.Regressed).Error; err != nil {
		return nil, err
	}
	report.Stats.RegressedCount = len(report.Regressed)

	return report, nil
}

// GetFamilyStats returns a map of Family Name -> Count of Open Findings active in the last N days.
// Note: Days argument is currently ignored to show global stats.
func (s *SQLiteStore) GetFamilyStats(days int) (map[string]int, error) {
	stats := make(map[string]int)

	type Result struct {
		Family string
		Count  int
	}

	var results []Result
	// Join Findings -> Vulnerabilities
	// Filter by Open findings seen recently
	// Group by Vuln.Family
	err := s.db.Table("findings").
		Select("vulnerabilities.family, count(*) as count").
		Joins("JOIN vulnerabilities ON vulnerabilities.id = findings.vulnerability_id").
		Where("findings.status = ?", "Open").
		Group("vulnerabilities.family").
		Order("count desc").
		Scan(&results).Error

	if err != nil {
		return nil, err
	}

	for _, r := range results {
		if r.Family == "" {
			stats["Unknown"] = r.Count
		} else {
			stats[r.Family] = r.Count
		}
	}

	return stats, nil
}

// GetFindingsForExport returns all findings (Open, Fixed, Snoozed) for CSV export.
func (s *SQLiteStore) GetFindingsForExport(hostID uint) ([]models.Finding, error) {
	var findings []models.Finding
	query := s.db.Preload("Vuln").Preload("Host")

	if hostID > 0 {
		query = query.Where("host_id = ?", hostID)
	}

	err := query.Find(&findings).Error
	return findings, err
}
