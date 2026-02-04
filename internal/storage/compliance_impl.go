package storage

import (
	"github.com/hootmeow/Vuln-Strix/internal/models"
)

// GetComplianceFrameworks returns all compliance frameworks.
func (s *SQLiteStore) GetComplianceFrameworks() ([]models.ComplianceFramework, error) {
	var frameworks []models.ComplianceFramework
	err := s.db.Order("name asc").Find(&frameworks).Error
	return frameworks, err
}

// GetComplianceControls returns all controls for a specific framework.
func (s *SQLiteStore) GetComplianceControls(frameworkID uint) ([]models.ComplianceControl, error) {
	var controls []models.ComplianceControl
	err := s.db.Where("framework_id = ?", frameworkID).Order("control_id asc").Find(&controls).Error
	return controls, err
}

// GetFrameworkStats returns compliance statistics for a framework.
func (s *SQLiteStore) GetFrameworkStats(frameworkCode string) (*FrameworkStats, error) {
	stats := &FrameworkStats{}

	// Get framework
	var framework models.ComplianceFramework
	if err := s.db.Where("code = ?", frameworkCode).First(&framework).Error; err != nil {
		return stats, err
	}

	// Count total controls
	var totalControls int64
	s.db.Model(&models.ComplianceControl{}).Where("framework_id = ?", framework.ID).Count(&totalControls)
	stats.TotalControls = int(totalControls)

	// Count controls that have vulnerability mappings
	var mappedControls int64
	s.db.Model(&models.ComplianceControl{}).
		Where("framework_id = ?", framework.ID).
		Where("id IN (SELECT DISTINCT control_id FROM vulnerability_compliance_mappings)").
		Count(&mappedControls)
	stats.MappedControls = int(mappedControls)

	// Count violated controls (controls mapped to vulnerabilities with open findings)
	var violatedControls int64
	s.db.Model(&models.ComplianceControl{}).
		Joins("JOIN vulnerability_compliance_mappings ON vulnerability_compliance_mappings.control_id = compliance_controls.id").
		Joins("JOIN vulnerabilities ON vulnerabilities.id = vulnerability_compliance_mappings.vulnerability_id").
		Joins("JOIN findings ON findings.vulnerability_id = vulnerabilities.id").
		Where("compliance_controls.framework_id = ? AND findings.status = ?", framework.ID, "Open").
		Distinct("compliance_controls.id").
		Count(&violatedControls)
	stats.ViolatedCount = int(violatedControls)

	// Calculate compliance rate
	if stats.TotalControls > 0 {
		stats.ComplianceRate = float64(stats.TotalControls-stats.ViolatedCount) / float64(stats.TotalControls) * 100
	}

	// Count critical and high gaps
	type GapCount struct {
		Severity string
		Count    int
	}
	var gapCounts []GapCount
	s.db.Model(&models.Finding{}).
		Select("vulnerabilities.severity, COUNT(DISTINCT compliance_controls.id) as count").
		Joins("JOIN vulnerabilities ON vulnerabilities.id = findings.vulnerability_id").
		Joins("JOIN vulnerability_compliance_mappings ON vulnerability_compliance_mappings.vulnerability_id = vulnerabilities.id").
		Joins("JOIN compliance_controls ON compliance_controls.id = vulnerability_compliance_mappings.control_id").
		Where("compliance_controls.framework_id = ? AND findings.status = ?", framework.ID, "Open").
		Group("vulnerabilities.severity").
		Scan(&gapCounts)

	for _, gc := range gapCounts {
		switch gc.Severity {
		case "Critical":
			stats.CriticalGaps = gc.Count
		case "High":
			stats.HighGaps = gc.Count
		}
	}

	return stats, nil
}

// GetComplianceGaps returns compliance gaps (violated controls) for a framework.
func (s *SQLiteStore) GetComplianceGaps(frameworkCode string) ([]ComplianceGap, error) {
	var gaps []ComplianceGap

	// Get framework
	var framework models.ComplianceFramework
	if err := s.db.Where("code = ?", frameworkCode).First(&framework).Error; err != nil {
		return gaps, err
	}

	// Get controls with open findings
	type GapResult struct {
		ControlID       uint
		ControlIDStr    string `gorm:"column:control_id_str"`
		ControlTitle    string
		VulnID          uint
		VulnName        string
		Severity        string
		AffectedHosts   int
	}

	var results []GapResult
	err := s.db.Table("compliance_controls").
		Select(`compliance_controls.id as control_id,
				compliance_controls.control_id as control_id_str,
				compliance_controls.title as control_title,
				vulnerabilities.id as vuln_id,
				vulnerabilities.name as vuln_name,
				vulnerabilities.severity,
				COUNT(DISTINCT findings.host_id) as affected_hosts`).
		Joins("JOIN vulnerability_compliance_mappings ON vulnerability_compliance_mappings.control_id = compliance_controls.id").
		Joins("JOIN vulnerabilities ON vulnerabilities.id = vulnerability_compliance_mappings.vulnerability_id").
		Joins("JOIN findings ON findings.vulnerability_id = vulnerabilities.id").
		Where("compliance_controls.framework_id = ? AND findings.status = ?", framework.ID, "Open").
		Group("compliance_controls.id, vulnerabilities.id").
		Order("vulnerabilities.severity desc, affected_hosts desc").
		Scan(&results).Error

	if err != nil {
		return gaps, err
	}

	for _, r := range results {
		gaps = append(gaps, ComplianceGap{
			Control: models.ComplianceControl{
				ControlID: r.ControlIDStr,
				Title:     r.ControlTitle,
			},
			Vulnerability: models.Vulnerability{
				Name: r.VulnName,
			},
			AffectedHosts: r.AffectedHosts,
			Severity:      r.Severity,
		})
	}

	return gaps, nil
}

// CreateComplianceMapping creates a vulnerability-to-control mapping.
func (s *SQLiteStore) CreateComplianceMapping(vulnID, controlID uint, source string) error {
	mapping := models.VulnerabilityComplianceMapping{
		VulnerabilityID: vulnID,
		ControlID:       controlID,
		MappingSource:   source,
	}
	return s.db.Create(&mapping).Error
}

// GetVulnerabilityMappings returns all compliance mappings for a vulnerability.
func (s *SQLiteStore) GetVulnerabilityMappings(vulnID uint) ([]models.VulnerabilityComplianceMapping, error) {
	var mappings []models.VulnerabilityComplianceMapping
	err := s.db.Preload("Control").Preload("Control.Framework").
		Where("vulnerability_id = ?", vulnID).
		Find(&mappings).Error
	return mappings, err
}
