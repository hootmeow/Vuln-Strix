package storage

import (
	"time"

	"github.com/hootmeow/Vuln-Strix/internal/models"
)

// AddHostTag adds a tag to a host. If the tag doesn't exist, it creates it.
func (s *SQLiteStore) AddHostTag(hostID uint, tagName string, color string) error {
	// 1. Get or Create Tag
	var tag models.Tag
	// Default color if empty
	if color == "" {
		color = "#6c757d" // Secondary grey
	}

	err := s.db.FirstOrCreate(&tag, models.Tag{Name: tagName, Color: color}).Error
	if err != nil {
		return err
	}

	// 2. Associate with Host
	var host models.Host
	if err := s.db.First(&host, hostID).Error; err != nil {
		return err
	}

	return s.db.Model(&host).Association("Tags").Append(&tag)
}

// RemoveHostTag removes a tag from a host.
func (s *SQLiteStore) RemoveHostTag(hostID uint, tagName string) error {
	var host models.Host
	if err := s.db.First(&host, hostID).Error; err != nil {
		return err
	}

	var tag models.Tag
	if err := s.db.Where("name = ?", tagName).First(&tag).Error; err != nil {
		return err // Tag not found, maybe ignore?
	}

	return s.db.Model(&host).Association("Tags").Delete(&tag)
}

// SnoozeFinding updates a finding to be snoozed until a future date.
func (s *SQLiteStore) SnoozeFinding(findingID uint, days int, reason string) error {
	until := time.Now().AddDate(0, 0, days)
	return s.db.Model(&models.Finding{}).Where("id = ?", findingID).Updates(map[string]interface{}{
		"snoozed_until":    until,
		"exception_reason": reason,
		"status":           "Snoozed", // Matches frontend check
	}).Error
}

// UpdateRunbook sets the Runbook URL for a vulnerability.
func (s *SQLiteStore) UpdateRunbook(vulnID uint, url string) error {
	return s.db.Model(&models.Vulnerability{}).Where("id = ?", vulnID).Update("runbook_url", url).Error
}
