package feed

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/hootmeow/Vuln-Strix/internal/storage"
)

const CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type CISAFeed struct {
	Title           string         `json:"title"`
	CatalogVersion  string         `json:"catalogVersion"`
	DateReleased    time.Time      `json:"dateReleased"`
	Count           int            `json:"count"`
	Vulnerabilities []CISAVulnItem `json:"vulnerabilities"`
}

type CISAVulnItem struct {
	CveID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
}

// UpdateKEV downloads the CISA feed and updates local vulnerabilities
func UpdateKEV(store storage.Store) error {
	log.Println("Starting CISA KEV Feed Update...")

	// 1. Download Feed
	resp, err := http.Get(CISA_KEV_URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var feed CISAFeed
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return err
	}

	// 2. Build Set of KEV CVEs
	kevMap := make(map[string]bool)
	for _, v := range feed.Vulnerabilities {
		kevMap[v.CveID] = true
	}
	log.Printf("Loaded %d KEV CVEs from CISA.", len(kevMap))

	// 3. Find Vulnerabilities to Update
	// We need to fetch all vulns that have CVEs defined
	// Since Store interface might not expose raw DB access, we might need to add a method
	// Or use GetVulnerabilities and iterate (memory heavy but okay for <100k vulns)

	vulns, err := store.GetVulnerabilities()
	if err != nil {
		return err
	}

	updatedCount := 0
	for _, v := range vulns {
		if v.CVEs == "" {
			continue
		}

		// Split stored CVEs (comma separated)
		cves := strings.Split(v.CVEs, ",")
		isExploited := false
		for _, cve := range cves {
			cve = strings.TrimSpace(cve)
			if kevMap[cve] {
				isExploited = true
				break
			}
		}

		if isExploited != v.InKEV {
			v.InKEV = isExploited
			// We need a way to store this back. UpsertVulnerability should work.
			if err := store.UpsertVulnerability(&v); err != nil {
				log.Printf("Failed to update KEV status for %s: %v", v.PluginID, err)
			} else {
				updatedCount++
			}
		}
	}

	log.Printf("CISA KEV Update Complete. Updated %d vulnerabilities.", updatedCount)
	return nil
}
