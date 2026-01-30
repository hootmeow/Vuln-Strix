package sampledata

import (
	"encoding/xml"
	"fmt"
	"math/rand"
	"os"
	"time"
)

type NessusClientData_v2 struct {
	XMLName xml.Name `xml:"NessusClientData_v2"`
	Policy  Policy   `xml:"Policy"`
	Report  Report   `xml:"Report"`
}

type Policy struct {
	PolicyName  string      `xml:"policyName"`
	Preferences Preferences `xml:"Preferences"`
}

type Preferences struct {
	ServerPreferences []Preference `xml:"ServerPreferences>preference"`
}

type Preference struct {
	Name  string `xml:"name"`
	Value string `xml:"value"`
}

type Report struct {
	Name       string       `xml:"name,attr"`
	ReportHost []ReportHost `xml:"ReportHost"`
}

type ReportHost struct {
	Name           string         `xml:"name,attr"`
	HostProperties HostProperties `xml:"HostProperties"`
	ReportItem     []ReportItem   `xml:"ReportItem"`
}

type HostProperties struct {
	Tag []Tag `xml:"tag"`
}

type Tag struct {
	Name string `xml:"name,attr"`
	Text string `xml:",chardata"`
}

type ReportItem struct {
	PluginID     string `xml:"pluginID,attr"`
	PluginName   string `xml:"pluginName,attr"`
	PluginFamily string `xml:"pluginFamily,attr"`
	Port         int    `xml:"port,attr"`
	Protocol     string `xml:"protocol,attr"`
	Severity     string `xml:"severity,attr"`
	Description  string `xml:"description"`
	Solution     string `xml:"solution"`
}

// Generate creates sample scan files in the specified directory.
func Generate(outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	// 1. Old Baseline Scan (-95 days ago)
	if err := generateRandomScan(outputDir, "scan1_baseline.nessus", "Baseline Scan", -95, 50, false); err != nil {
		return err
	}

	// 2. Mid-point Scan (-45 days ago) - Some remediation, some new, same hosts
	if err := generateRandomScan(outputDir, "scan2_mid.nessus", "Mid-Quarter Scan", -45, 50, true); err != nil {
		return err
	}

	// 3. Recent Scan (-2 days ago) - More remediation, new hosts
	if err := generateRandomScan(outputDir, "scan3_recent.nessus", "Recent Scan", -2, 55, true); err != nil {
		return err
	}

	return nil
}

func generateRandomScan(dir string, filename string, scanName string, daysOffset int, numHosts int, mutate bool) error {
	scanDate := time.Now().AddDate(0, 0, daysOffset)

	// Deterministic random seed per scan to be somewhat consistent but varied
	r := rand.New(rand.NewSource(int64(daysOffset + numHosts)))

	var hosts []ReportHost

	possibleOS := []string{
		"Windows Server 2019 Standard", "Windows Server 2016 Datacenter",
		"Ubuntu 20.04 LTS", "Ubuntu 22.04 LTS", "CentOS Linux 7",
		"Red Hat Enterprise Linux 8.4",
	}

	for i := 0; i < numHosts; i++ {
		ip := fmt.Sprintf("192.168.1.%d", 100+i)
		osName := possibleOS[r.Intn(len(possibleOS))]
		hostname := fmt.Sprintf("host-%d.local", 100+i)

		startTime := scanDate.Format(time.UnixDate)
		endTime := scanDate.Add(30 * time.Minute).Format(time.UnixDate)

		host := ReportHost{
			Name: ip,
			HostProperties: HostProperties{
				Tag: []Tag{
					{Name: "host-ip", Text: ip},
					{Name: "host-fqdn", Text: hostname},
					{Name: "operating-system", Text: osName},
					{Name: "HOST_START", Text: startTime},
					{Name: "HOST_END", Text: endTime},
				},
			},
			ReportItem: []ReportItem{},
		}

		// Add Vulnerabilities
		// Mutate logic: varying severity or presence based on random chance interacting with 'mutate'
		// If mutate is true, we might skip some (simulating fix) or add new ones.

		// 1. Always present: SMB or SSH Issue based on OS
		if contains(osName, "Windows") {
			if !mutate || r.Float32() > 0.3 { // 30% chance to be fixed if mutating
				host.ReportItem = append(host.ReportItem, ReportItem{
					PluginID: "10443", PluginName: "Microsoft Windows SMB NTLMv1 Authentication Enabled", PluginFamily: "Windows",
					Port: 445, Protocol: "tcp", Severity: "3", Description: "The remote Windows host has NTLMv1 enabled.", Solution: "Disable NTLMv1.",
				})
			}
		} else {
			if !mutate || r.Float32() > 0.3 {
				host.ReportItem = append(host.ReportItem, ReportItem{
					PluginID: "10002", PluginName: "Outdated SSH Server", PluginFamily: "General",
					Port: 22, Protocol: "tcp", Severity: "2", Description: "The remote SSH server is outdated.", Solution: "Upgrade SSH.",
				})
			}
		}

		// 2. Random Criticals (Log4j, etc.)
		if r.Float32() > 0.8 { // 20% of hosts have a critical
			host.ReportItem = append(host.ReportItem, ReportItem{
				PluginID: "156014", PluginName: "Apache Log4j Core RCE", PluginFamily: "CGI Abuses",
				Port: 8080, Protocol: "tcp", Severity: "4", Description: "Apache Log4j is vulnerable to RCE.", Solution: "Upgrade Log4j.",
			})
		}

		// 3. Old legacy stuff (present in baseline, maybe fixed later)
		if daysOffset < -90 && r.Float32() > 0.5 {
			host.ReportItem = append(host.ReportItem, ReportItem{
				PluginID: "41028", PluginName: "SNMP Agent Default Community Name (public)", PluginFamily: "SNMP",
				Port: 161, Protocol: "udp", Severity: "3", Description: "SNMP agent uses default community string.", Solution: "Disable SNMP or change community string.",
			})
		}

		hosts = append(hosts, host)
	}

	data := NessusClientData_v2{
		Policy: Policy{PolicyName: scanName},
		Report: Report{Name: scanName, ReportHost: hosts},
	}

	return writeFile(dir+"/"+filename, data)
}

func writeFile(path string, data NessusClientData_v2) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write([]byte(xml.Header)); err != nil {
		return err
	}
	enc := xml.NewEncoder(f)
	enc.Indent("", "  ")
	if err := enc.Encode(data); err != nil {
		return err
	}
	fmt.Printf("Created %s\n", path)
	return nil
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[0:len(substr)] != substr // Hacky string check, stdlib strings.Contains better but keeping imports minimal if needed
}

// Mapping Category to struct field shim
func (r ReportItem) Category(s string) {
	// struct tag hack
}
