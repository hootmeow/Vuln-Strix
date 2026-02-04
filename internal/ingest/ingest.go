package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"strings"
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
		startStr := rh.HostProperties.Get("HOST_START") // "Sat Nov  1 00:13:05 EDT 2025" or similar
		endStr := rh.HostProperties.Get("HOST_END")

		// Try multiple Nessus date formats
		layouts := []string{
			"Mon Jan 2 15:04:05 MST 2006",  // With timezone, single-digit day
			"Mon Jan 02 15:04:05 MST 2006", // With timezone, two-digit day
			"Mon Jan 2 15:04:05 2006",      // No timezone, single-digit day
			"Mon Jan 02 15:04:05 2006",     // No timezone, two-digit day
		}

		// Normalize multiple spaces to single space
		startStr = strings.Join(strings.Fields(startStr), " ")
		endStr = strings.Join(strings.Fields(endStr), " ")

		for _, layout := range layouts {
			if t, err := time.Parse(layout, startStr); err == nil {
				if scanStart.IsZero() || t.Before(scanStart) {
					scanStart = t
				}
				break
			}
		}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, endStr); err == nil {
				if scanEnd.IsZero() || t.After(scanEnd) {
					scanEnd = t
				}
				break
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
			IP:          ip,
			Hostname:    rh.HostProperties.Get("host-fqdn"),
			OS:          rh.HostProperties.Get("operating-system"),
			Criticality: "Medium", // Default for new assets
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
				Solution:    item.Solution,
				Severity:    mapSeverity(item.Severity),
				Family:      item.PluginFamily,
				CVEs:        strings.Join(item.CVE, ","),
				Compliance:  parseCompliance(item.Xref),
			}

			if err := store.UpsertVulnerability(vuln); err != nil {
				log.Printf("Error upserting vuln %s: %v", vuln.PluginID, err)
				continue
			}

			// 3. Create/Update Finding (State)
			fingerprint := generateFingerprint(host.IP, item.PluginID, item.Port, item.Protocol)

			finding := &models.Finding{
				HostID:          host.ID,
				VulnerabilityID: vuln.ID,
				ScanID:          scan.ID,
				Port:            item.Port,
				Protocol:        item.Protocol,
				Fingerprint:     fingerprint,
				Status:          "Open",
				LastSeen:        scanTime,
			}

			// Check if exists
			existing, err := store.FindFindingByFingerprint(fingerprint)
			if err == nil && existing != nil {
				// Update
				if existing.Status == "Fixed" {
					existing.ReopenCount++
					existing.FixedAt = time.Time{} // Clear FixedAt since it's reopened
					log.Printf("Zombie detected: %s on %s", existing.Fingerprint, host.IP)
				}
				existing.LastSeen = scanTime
				existing.ScanID = scan.ID // Update to current scan
				existing.Status = "Open"
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

	log.Printf("Scan %d stats: Critical=%d, High=%d, Medium=%d, Low=%d", scan.ID, crit, high, med, low)

	if err := store.UpdateScan(scan); err != nil {
		log.Printf("Error updating scan stats for scan %d: %v", scan.ID, err)
	}

	log.Printf("Ingestion complete. Scan ID: %d, Name: %s", scan.ID, scan.Name)
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

func parseCompliance(xrefs []string) string {
	var compliance []string
	for _, ref := range xrefs {
		// Common keys: "PCI-DSS", "NIST", "CIS", "HIPAA", "ISO"
		upper := strings.ToUpper(ref)
		if strings.Contains(upper, "PCI") ||
			strings.Contains(upper, "NIST") ||
			strings.Contains(upper, "CIS") ||
			strings.Contains(upper, "HIPAA") ||
			strings.Contains(upper, "ISO") {
			compliance = append(compliance, ref)
		}
	}
	return strings.Join(compliance, ", ")
}
