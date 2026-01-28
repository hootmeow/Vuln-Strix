package sampledata

import (
	"encoding/xml"
	"fmt"
	"os"
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

	if err := generateScan1(outputDir); err != nil {
		return err
	}
	if err := generateScan2(outputDir); err != nil {
		return err
	}
	// Add more sample data as requested
	if err := generateScan3(outputDir); err != nil {
		return err
	}

	return nil
}

func generateScan1(dir string) error {
	data := NessusClientData_v2{
		Policy: Policy{
			PolicyName: "Advanced Dynamic Scan",
			Preferences: Preferences{
				ServerPreferences: []Preference{
					{Name: "plugin_set", Value: "202512210331"},
				},
			},
		},
		Report: Report{
			Name: "Scan 1 (Baseline)",
			ReportHost: []ReportHost{
				{
					Name: "192.168.1.100",
					HostProperties: HostProperties{
						Tag: []Tag{
							{Name: "host-ip", Text: "192.168.1.100"},
							{Name: "host-fqdn", Text: "server-a.local"},
							{Name: "operating-system", Text: "Linux Kernel 5.x"},
							{Name: "HOST_START", Text: "Sat Oct 25 10:00:00 2025"},
							{Name: "HOST_END", Text: "Sat Oct 25 10:30:00 2025"},
						},
					},
					ReportItem: []ReportItem{
						{
							PluginID: "10001", PluginName: "Weak Password", PluginFamily: "General",
							Port: 22, Protocol: "tcp", Severity: "3", Description: "The remote host has a weak password.",
							Solution: "Enforce a strong password policy.",
						},
						{
							PluginID: "10002", PluginName: "Outdated SSH", PluginFamily: "General",
							Port: 22, Protocol: "tcp", Severity: "2", Description: "The remote SSH server is outdated.",
							Solution: "Update the SSH server to the latest version.",
						},
					},
				},
			},
		},
	}
	return writeFile(dir+"/scan1_baseline.nessus", data)
}

func generateScan2(dir string) error {
	data := NessusClientData_v2{
		Policy: Policy{
			PolicyName: "Basic Network Scan",
			Preferences: Preferences{
				ServerPreferences: []Preference{
					{Name: "plugin_set", Value: "202601280000"},
				},
			},
		},
		Report: Report{
			Name: "Scan 2 (Remediation Check)",
			ReportHost: []ReportHost{
				{
					Name: "192.168.1.100",
					HostProperties: HostProperties{
						Tag: []Tag{
							{Name: "host-ip", Text: "192.168.1.100"},
							{Name: "host-fqdn", Text: "server-a.local"},
							{Name: "operating-system", Text: "Linux Kernel 5.x"},
							{Name: "HOST_START", Text: "Sun Dec 14 10:00:00 2025"},
							{Name: "HOST_END", Text: "Sun Dec 14 10:15:00 2025"},
						},
					},
					ReportItem: []ReportItem{
						{
							PluginID: "10001", PluginName: "Weak Password", PluginFamily: "General",
							Port: 22, Protocol: "tcp", Severity: "3", Description: "The remote host has a weak password.",
							Solution: "Enforce a strong password policy.",
						},
					},
				},
				{
					Name: "192.168.1.101",
					HostProperties: HostProperties{
						Tag: []Tag{
							{Name: "host-ip", Text: "192.168.1.101"},
							{Name: "host-fqdn", Text: "server-b.local"},
							{Name: "operating-system", Text: "Windows Server 2019"},
							{Name: "HOST_START", Text: "Sun Dec 14 10:10:00 2025"},
							{Name: "HOST_END", Text: "Sun Dec 14 10:20:00 2025"},
						},
					},
					ReportItem: []ReportItem{
						{
							PluginID: "20001", PluginName: "SMB Signing Disabled", PluginFamily: "Windows",
							Port: 445, Protocol: "tcp", Severity: "2", Description: "SMB signing is not enforced.",
							Solution: "Enforce SMB signing in Group Policy.",
						},
					},
				},
			},
		},
	}
	return writeFile(dir+"/scan2_remediation.nessus", data)
}

func generateScan3(dir string) error {
	// Monthly Patch Audit
	data := NessusClientData_v2{
		Policy: Policy{
			PolicyName: "Credentialed Patch Audit",
			Preferences: Preferences{
				ServerPreferences: []Preference{
					{Name: "plugin_set", Value: "202602150000"},
				},
			},
		},
		Report: Report{
			Name: "Scan 3 (Monthly Patching)",
			ReportHost: []ReportHost{
				{
					Name: "192.168.1.100",
					HostProperties: HostProperties{
						Tag: []Tag{
							{Name: "host-ip", Text: "192.168.1.100"},
							{Name: "host-fqdn", Text: "server-a.local"},
							{Name: "operating-system", Text: "Linux Kernel 5.x"},
							{Name: "HOST_START", Text: "Wed Jan 28 02:00:00 2026"},
							{Name: "HOST_END", Text: "Wed Jan 28 02:25:00 2026"},
						},
					},
					ReportItem: []ReportItem{
						// Weak Password still there? No, let's say it's fixed.
						// New vuln detected
						{
							PluginID: "30215", PluginName: "Apache Log4j RCE", PluginFamily: "CGI Abuses",
							Port: 8080, Protocol: "tcp", Severity: "4", Description: "Apache Log4j is vulnerable to RCE.",
							Solution: "Upgrade Log4j to version 2.17.1 or higher.",
						},
					},
				},
				{
					Name: "192.168.1.102", // New Host
					HostProperties: HostProperties{
						Tag: []Tag{
							{Name: "host-ip", Text: "192.168.1.102"},
							{Name: "host-fqdn", Text: "db-prod.local"},
							{Name: "operating-system", Text: "Ubuntu 20.04"},
							{Name: "HOST_START", Text: "Wed Jan 28 02:30:00 2026"},
							{Name: "HOST_END", Text: "Wed Jan 28 02:55:00 2026"},
						},
					},
					ReportItem: []ReportItem{
						{
							PluginID: "10002", PluginName: "Outdated SSH", PluginFamily: "General",
							Port: 22, Protocol: "tcp", Severity: "2", Description: "The remote SSH server is outdated.",
							Solution: "Update the SSH server to the latest version.",
						},
					},
				},
			},
		},
	}
	return writeFile(dir+"/scan3_patch_audit.nessus", data)
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
