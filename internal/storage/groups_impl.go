package storage

import (
	"github.com/hootmeow/Vuln-Strix/internal/models"
)

// GetTagsByCategory returns all tags of a specific category. If category is empty, returns all tags.
func (s *SQLiteStore) GetTagsByCategory(category string) ([]models.Tag, error) {
	var tags []models.Tag
	query := s.db.Model(&models.Tag{})
	if category != "" {
		query = query.Where("category = ?", category)
	}
	err := query.Order("name asc").Find(&tags).Error
	return tags, err
}

// GetAssetGroups returns all non-General tags with host counts and statistics.
func (s *SQLiteStore) GetAssetGroups() ([]AssetGroup, error) {
	var tags []models.Tag
	err := s.db.Where("category != ?", models.TagCategoryGeneral).Order("category, name").Find(&tags).Error
	if err != nil {
		return nil, err
	}

	var groups []AssetGroup
	for _, tag := range tags {
		stats, _ := s.GetGroupStats(tag.Name)
		hostCount := 0
		if stats != nil {
			hostCount = stats.TotalHosts
		}
		groups = append(groups, AssetGroup{
			Tag:       tag,
			HostCount: hostCount,
			Stats:     *stats,
		})
	}
	return groups, nil
}

// GetHostsByTag returns all hosts with a specific tag.
func (s *SQLiteStore) GetHostsByTag(tagName string) ([]models.Host, error) {
	var hosts []models.Host
	err := s.db.Joins("JOIN host_tags ON host_tags.host_id = hosts.id").
		Joins("JOIN tags ON tags.id = host_tags.tag_id").
		Where("tags.name = ?", tagName).
		Preload("Tags").
		Find(&hosts).Error
	return hosts, err
}

// GetGroupStats returns vulnerability statistics for hosts with a specific tag.
func (s *SQLiteStore) GetGroupStats(tagName string) (*GroupStats, error) {
	stats := &GroupStats{}

	// Get host count
	var hostCount int64
	err := s.db.Model(&models.Host{}).
		Joins("JOIN host_tags ON host_tags.host_id = hosts.id").
		Joins("JOIN tags ON tags.id = host_tags.tag_id").
		Where("tags.name = ?", tagName).
		Count(&hostCount).Error
	if err != nil {
		return nil, err
	}
	stats.TotalHosts = int(hostCount)

	// Get finding counts by severity for hosts in this group
	type SeverityCount struct {
		Severity string
		Count    int
	}
	var counts []SeverityCount

	err = s.db.Model(&models.Finding{}).
		Select("vulnerabilities.severity as severity, COUNT(*) as count").
		Joins("JOIN vulnerabilities ON vulnerabilities.id = findings.vulnerability_id").
		Joins("JOIN hosts ON hosts.id = findings.host_id").
		Joins("JOIN host_tags ON host_tags.host_id = hosts.id").
		Joins("JOIN tags ON tags.id = host_tags.tag_id").
		Where("tags.name = ? AND findings.status = ?", tagName, "Open").
		Group("vulnerabilities.severity").
		Scan(&counts).Error
	if err != nil {
		return nil, err
	}

	for _, c := range counts {
		switch c.Severity {
		case "Critical":
			stats.CriticalCount = c.Count
		case "High":
			stats.HighCount = c.Count
		case "Medium":
			stats.MediumCount = c.Count
		case "Low":
			stats.LowCount = c.Count
		}
		stats.OpenFindings += c.Count
	}

	return stats, nil
}

// GetFindingsByTag returns all open findings for hosts with a specific tag.
func (s *SQLiteStore) GetFindingsByTag(tagName string) ([]models.Finding, error) {
	var findings []models.Finding
	err := s.db.Preload("Vuln").Preload("Host").
		Joins("JOIN hosts ON hosts.id = findings.host_id").
		Joins("JOIN host_tags ON host_tags.host_id = hosts.id").
		Joins("JOIN tags ON tags.id = host_tags.tag_id").
		Where("tags.name = ? AND findings.status = ?", tagName, "Open").
		Order("findings.created_at desc").
		Find(&findings).Error
	return findings, err
}

// CreateGroup creates a new group tag with the specified category.
func (s *SQLiteStore) CreateGroup(tag *models.Tag) error {
	return s.db.Create(tag).Error
}

// UpdateGroup updates a group's name, color, and icon.
func (s *SQLiteStore) UpdateGroup(id uint, name, color, icon string) error {
	updates := map[string]interface{}{}
	if name != "" {
		updates["name"] = name
	}
	if color != "" {
		updates["color"] = color
	}
	if icon != "" {
		updates["icon"] = icon
	}
	return s.db.Model(&models.Tag{}).Where("id = ?", id).Updates(updates).Error
}

// DeleteGroup deletes a group tag and removes associations.
func (s *SQLiteStore) DeleteGroup(id uint) error {
	// Remove host_tags associations first
	if err := s.db.Exec("DELETE FROM host_tags WHERE tag_id = ?", id).Error; err != nil {
		return err
	}
	return s.db.Delete(&models.Tag{}, id).Error
}

// GetGroupByID returns a tag by its ID.
func (s *SQLiteStore) GetGroupByID(id uint) (*models.Tag, error) {
	var tag models.Tag
	err := s.db.First(&tag, id).Error
	return &tag, err
}
