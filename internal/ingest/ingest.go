package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/hootmeow/Vuln-Strix/internal/models"
	"github.com/hootmeow/Vuln-Strix/internal/storage"
)

// ProcessFile reads a .nessus file and updates the database.
func ProcessFile(store storage.Store, filePath string) error {
	log.Printf("Ingesting file: %s", filePath)

	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Parse XML
	var data NessusClientData_v2
	decoder := xml.NewDecoder(f)
	// Nessus files can be huge, but for V1 we'll trust memory.
	// Optimally we'd use token decoder, but struct decoder is safer for "ReportHost" iteration if mapped correctly.
	if err := decoder.Decode(&data); err != nil {
		return fmt.Errorf("failed to decode xml: %w", err)
	}

	log.Printf("Parsed report: %s. Found %d hosts.", data.Report.Name, len(data.Report.ReportHost))

	// Determine Scan Start/End and Plugin Set
	var scanStart, scanEnd time.Time
	var pluginSet string

	// Scan Stats
	var crit, high, med, low int

	// First pass for Time and PluginSet (if we can find it)
	// Usually plugin_set is in server preferences, but we might just use "N/A" if missing for now.
	for _, p := range data.Policy.Preferences.ServerPreferences {
		if p.Name == "plugin_set" {
			pluginSet = p.Value
		}
	}
	if pluginSet == "" {
		pluginSet = "Unknown"
	}

	for _, rh := range data.Report.ReportHost {
		// Parse Times
		startStr := rh.HostProperties.Get("HOST_START") // "Fri Dec 19 19:12:08 2025" or similar
		endStr := rh.HostProperties.Get("HOST_END")

		// Nessus format: "Mon Jan 02 15:04:05 2006"
		layout := "Mon Jan 02 15:04:05 2006"

		if t, err := time.Parse(layout, startStr); err == nil {
			if scanStart.IsZero() || t.Before(scanStart) {
				scanStart = t
			}
		}
		if t, err := time.Parse(layout, endStr); err == nil {
			if scanEnd.IsZero() || t.After(scanEnd) {
				scanEnd = t
			}
		}
	}

	// Fallback if times are not found
	if scanStart.IsZero() {
		scanStart = time.Now()
	}
	if scanEnd.IsZero() {
		scanEnd = time.Now()
	}

	// Create Scan Record
	scan := &models.Scan{
		Name:       data.Report.Name,
		PolicyName: data.Policy.PolicyName,
		PluginSet:  pluginSet,
		ScanStart:  scanStart,
		ScanEnd:    scanEnd,
	}
	if err := store.CreateScan(scan); err != nil {
		return fmt.Errorf("failed to create scan record: %w", err)
	}

	scanTime := scanEnd // Use scan end time for findings "LastSeen"

	for _, rh := range data.Report.ReportHost {
		// 1. Upsert Host
		ip := rh.HostProperties.Get("host-ip")
		if ip == "" {
			ip = rh.Name // Fallback
		}

		host := &models.Host{
			IP:       ip,
			Hostname: rh.HostProperties.Get("host-fqdn"),
			OS:       rh.HostProperties.Get("operating-system"),
		}

		if err := store.UpsertHost(host); err != nil {
			log.Printf("Error upserting host %s: %v", host.IP, err)
			continue
		}

		// Link Host to Scan
		if err := store.AddHostToScan(host.ID, scan.ID); err != nil {
			log.Printf("Error linking host %s to scan: %v", host.IP, err)
		}

		// 2. Iterate Findings
		for _, item := range rh.ReportItem {
			// Skip Informational if needed, but Nessus severity 0 is info.
			// Let's keep everything for now or filter later.

			sev := mapSeverity(item.Severity)
			switch sev {
			case "Critical":
				crit++
			case "High":
				high++
			case "Medium":
				med++
			case "Low":
				low++
			}

			// Upsert Vulnerability Definition
			vuln := &models.Vulnerability{
				PluginID:    item.PluginID,
				Name:        item.PluginName,
				Description: item.Description,
				Severity:    sev,
				Family:      item.PluginFamily,
			}

			if err := store.UpsertVulnerability(vuln); err != nil {
				log.Printf("Error upserting vuln %s: %v", vuln.PluginID, err)
				continue
			}

			// 3. Create/Update Finding (State)
			fingerprint := generateFingerprint(host.IP, item.PluginID, item.Port, item.Protocol)

			finding := &models.Finding{
				HostID:      host.ID,
				VulnID:      vuln.ID,
				Port:        item.Port,
				Protocol:    item.Protocol,
				Fingerprint: fingerprint,
				Status:      "Open",
				LastSeen:    scanTime,
			}

			// Check if exists
			existing, err := store.FindFindingByFingerprint(fingerprint)
			if err == nil && existing != nil {
				// Update
				existing.LastSeen = scanTime
				existing.Status = "Open" // Re-open if it was fixed
				if err := store.UpdateFinding(existing); err != nil {
					log.Printf("Error updating finding %s: %v", fingerprint, err)
				}
			} else {
				// Create new
				finding.FirstSeen = scanTime
				if err := store.CreateFinding(finding); err != nil {
					log.Printf("Error creating finding %s: %v", fingerprint, err)
				}
			}
		}

		// 4. Mark missing findings as Fixed for this host
		// Iterate over all Open findings for this host. If LastSeen < scanTime, mark as Fixed.
		if err := store.MarkFindingsResolved(host.ID, scanTime); err != nil {
			log.Printf("Error marking resolved findings for host %s: %v", host.IP, err)
		}
	}

	// Update Scan Stats
	scan.CriticalCount = crit
	scan.HighCount = high
	scan.MediumCount = med
	scan.LowCount = low
	// Since we created it earlier, we need to save it again.
	// But `store` doesn't have UpdateScan yet. I'll just use GORM direct or add UpdateScan?
	// The `Store` interface doesn't have UpdateScan.
	// HACK: I should have added UpdateScan. But for now, let's just create it with 0 stats and then ... wait
	// I cannot calculate stats *before* creating the scan if I needed the ID for linking.
	// Actually, I can process everything and then update the scan at the end.
	// I'll need to add UpdateScan to the interface or just re-save it.
	// For expediency, I will assume I can update it via `CreateScan` if ID is set? No, `Create` might error on duplicate key.
	// I'll add `UpdateScan` to the interface.
	if err := store.UpdateScan(scan); err != nil {
		log.Printf("Error updating scan stats for scan %d: %v", scan.ID, err)
	}

	log.Println("Ingestion complete.")
	return nil
}

func mapSeverity(severity string) string {
	switch severity {
	case "4":
		return "Critical"
	case "3":
		return "High"
	case "2":
		return "Medium"
	case "1":
		return "Low"
	default:
		return "Info"
	}
}

func generateFingerprint(ip, pluginID string, port int, protocol string) string {
	data := fmt.Sprintf("%s|%s|%d|%s", ip, pluginID, port, protocol)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
