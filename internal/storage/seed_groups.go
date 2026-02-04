package storage

import (
	"log"

	"github.com/hootmeow/Vuln-Strix/internal/models"
)

// SeedDefaultGroups creates default asset group tags if they don't exist.
func (s *SQLiteStore) SeedDefaultGroups() error {
	groups := []models.Tag{
		// Business Units
		{Name: "Finance", Color: "#198754", Category: models.TagCategoryBusinessUnit, Icon: "dollar-sign"},
		{Name: "Engineering", Color: "#0d6efd", Category: models.TagCategoryBusinessUnit, Icon: "code"},
		{Name: "Sales", Color: "#6f42c1", Category: models.TagCategoryBusinessUnit, Icon: "trending-up"},
		{Name: "HR", Color: "#fd7e14", Category: models.TagCategoryBusinessUnit, Icon: "users"},
		{Name: "Operations", Color: "#20c997", Category: models.TagCategoryBusinessUnit, Icon: "settings"},

		// Environments
		{Name: "Production", Color: "#dc3545", Category: models.TagCategoryEnvironment, Icon: "server"},
		{Name: "Staging", Color: "#ffc107", Category: models.TagCategoryEnvironment, Icon: "layers"},
		{Name: "Development", Color: "#0dcaf0", Category: models.TagCategoryEnvironment, Icon: "git-branch"},
		{Name: "QA", Color: "#6c757d", Category: models.TagCategoryEnvironment, Icon: "check-circle"},

		// Network Segments
		{Name: "DMZ", Color: "#dc3545", Category: models.TagCategoryNetwork, Icon: "shield"},
		{Name: "Internal", Color: "#198754", Category: models.TagCategoryNetwork, Icon: "lock"},
		{Name: "Guest", Color: "#ffc107", Category: models.TagCategoryNetwork, Icon: "wifi"},
		{Name: "Management", Color: "#0d6efd", Category: models.TagCategoryNetwork, Icon: "terminal"},
	}

	for _, g := range groups {
		// Check if exists by name and category
		var existing models.Tag
		result := s.db.Where("name = ? AND category = ?", g.Name, g.Category).First(&existing)
		if result.Error != nil {
			// Create new
			if err := s.db.Create(&g).Error; err != nil {
				log.Printf("Failed to seed group %s: %v", g.Name, err)
			}
		}
	}

	log.Println("Default asset groups seeded")
	return nil
}
