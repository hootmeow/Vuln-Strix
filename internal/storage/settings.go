package storage

import (
	"strconv"

	"gorm.io/gorm"
)

// Setting represents a key-value configuration pair
type Setting struct {
	gorm.Model
	Key   string `gorm:"uniqueIndex;not null" json:"key"`
	Value string `json:"value"`
}

// GetSettings retrieves all settings as a map
func (s *SQLiteStore) GetSettings() (map[string]string, error) {
	var settings []Setting
	if err := s.db.Find(&settings).Error; err != nil {
		return nil, err
	}

	result := make(map[string]string)
	for _, setting := range settings {
		result[setting.Key] = setting.Value
	}
	return result, nil
}

// UpdateSetting creates or updates a setting
func (s *SQLiteStore) UpdateSetting(key, value string) error {
	var setting Setting
	return s.db.Where(Setting{Key: key}).Assign(Setting{Value: value}).FirstOrCreate(&setting).Error
}

// GetSLAConfig retrieves the SLA days for each severity (defaulting if not set)
func (s *SQLiteStore) GetSLAConfig() map[string]int {
	defaults := map[string]int{
		"Critical": 7,
		"High":     14,
		"Medium":   30,
		"Low":      60,
		"Info":     90,
	}

	stored, err := s.GetSettings()
	if err != nil {
		return defaults
	}

	for k := range defaults {
		if val, ok := stored["sla_"+k]; ok {
			if i, err := strconv.Atoi(val); err == nil && i > 0 {
				defaults[k] = i
			}
		}
	}
	return defaults
}
