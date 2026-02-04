package storage

import (
	"strings"

	"github.com/hootmeow/Vuln-Strix/internal/models"
)

func (s *SQLiteStore) GlobalSearch(criteria FilterCriteria, limit int) ([]SearchResult, error) {
	var results []SearchResult

	// Search hosts
	hosts, _ := s.SearchHosts(criteria)
	for _, h := range hosts {
		results = append(results, SearchResult{
			Type:     "host",
			ID:       h.ID,
			Title:    h.Hostname,
			Subtitle: h.IP,
			URL:      "/hosts/" + string(rune(h.ID)),
		})
	}

	// Search findings
	findings, _ := s.SearchFindings(criteria)
	for _, f := range findings {
		results = append(results, SearchResult{
			Type:     "finding",
			ID:       f.ID,
			Title:    f.Vuln.Name,
			Subtitle: f.Host.IP,
			Severity: f.Vuln.Severity,
		})
	}

	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func (s *SQLiteStore) SearchHosts(criteria FilterCriteria) ([]models.Host, error) {
	var hosts []models.Host
	query := s.db.Model(&models.Host{})

	if criteria.Query != "" {
		query = query.Where("hostname LIKE ? OR ip LIKE ?", "%"+criteria.Query+"%", "%"+criteria.Query+"%")
	}

	if len(criteria.Tags) > 0 {
		query = query.Joins("JOIN host_tags ON host_tags.host_id = hosts.id").
			Joins("JOIN tags ON tags.id = host_tags.tag_id").
			Where("tags.name IN ?", criteria.Tags)
	}

	err := query.Limit(100).Find(&hosts).Error
	return hosts, err
}

func (s *SQLiteStore) SearchFindings(criteria FilterCriteria) ([]models.Finding, error) {
	var findings []models.Finding
	query := s.db.Preload("Vuln").Preload("Host").Model(&models.Finding{})

	if criteria.Query != "" {
		query = query.Joins("JOIN vulnerabilities ON vulnerabilities.id = findings.vulnerability_id").
			Where("vulnerabilities.name LIKE ?", "%"+criteria.Query+"%")
	}

	if len(criteria.Severity) > 0 {
		query = query.Joins("JOIN vulnerabilities v ON v.id = findings.vulnerability_id").
			Where("v.severity IN ?", criteria.Severity)
	}

	if len(criteria.Status) > 0 {
		query = query.Where("findings.status IN ?", criteria.Status)
	}

	err := query.Limit(100).Find(&findings).Error
	return findings, err
}

func (s *SQLiteStore) GetSavedFilters() ([]models.SavedFilter, error) {
	var filters []models.SavedFilter
	err := s.db.Order("usage_count desc").Find(&filters).Error
	return filters, err
}

func (s *SQLiteStore) CreateSavedFilter(filter *models.SavedFilter) error {
	return s.db.Create(filter).Error
}

func (s *SQLiteStore) AddSearchHistory(query, userID string, resultCount int) error {
	history := models.SearchHistory{
		Query:       query,
		UserID:      userID,
		ResultCount: resultCount,
	}
	return s.db.Create(&history).Error
}

func (s *SQLiteStore) GetSearchSuggestions(prefix string, limit int) ([]string, error) {
	var suggestions []string
	if prefix == "" {
		return suggestions, nil
	}

	var histories []models.SearchHistory
	s.db.Where("query LIKE ?", prefix+"%").
		Group("query").
		Order("COUNT(*) DESC").
		Limit(limit).
		Find(&histories)

	for _, h := range histories {
		suggestions = append(suggestions, h.Query)
	}

	// Add DSL suggestions
	if strings.HasPrefix("severity:", prefix) || prefix == "s" {
		suggestions = append(suggestions, "severity:critical", "severity:high", "severity:medium")
	}
	if strings.HasPrefix("status:", prefix) || prefix == "st" {
		suggestions = append(suggestions, "status:open", "status:fixed")
	}

	return suggestions, nil
}
