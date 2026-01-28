package main

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
}

func main() {
	if err := os.MkdirAll("samples", 0755); err != nil {
		panic(err)
	}

	generateScan1()
	generateScan2()
}

func generateScan1() {
	// Host A has 2 vulns
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
							{Name: "HOST_START", Text: "Sun Dec 21 22:31:00 2025"},
							{Name: "HOST_END", Text: "Sun Dec 21 23:07:00 2025"},
						},
					},
					ReportItem: []ReportItem{
						{
							PluginID: "10001", PluginName: "Weak Password", PluginFamily: "General",
							Port: 22, Protocol: "tcp", Severity: "3", Description: "The remote host has a weak password.",
						},
						{
							PluginID: "10002", PluginName: "Outdated SSH", PluginFamily: "General",
							Port: 22, Protocol: "tcp", Severity: "2", Description: "The remote SSH server is outdated.",
						},
					},
				},
			},
		},
	}
	writeFile("samples/scan1_baseline.nessus", data)
}

func generateScan2() {
	// Host A has 1 vuln (10002 is fixed), but 10001 remains.
	// Added Host B.
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
							{Name: "HOST_START", Text: "Wed Jan 28 10:00:00 2026"},
							{Name: "HOST_END", Text: "Wed Jan 28 10:15:00 2026"},
						},
					},
					ReportItem: []ReportItem{
						{
							PluginID: "10001", PluginName: "Weak Password", PluginFamily: "General",
							Port: 22, Protocol: "tcp", Severity: "3", Description: "The remote host has a weak password.",
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
							{Name: "HOST_START", Text: "Wed Jan 28 10:10:00 2026"},
							{Name: "HOST_END", Text: "Wed Jan 28 10:20:00 2026"},
						},
					},
					ReportItem: []ReportItem{
						{
							PluginID: "20001", PluginName: "SMB Signing Disabled", PluginFamily: "Windows",
							Port: 445, Protocol: "tcp", Severity: "2", Description: "SMB signing is not enforced.",
						},
					},
				},
			},
		},
	}
	writeFile("samples/scan2_remediation.nessus", data)
}

func writeFile(path string, data NessusClientData_v2) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	if _, err := f.Write([]byte(xml.Header)); err != nil {
		panic(err)
	}
	enc := xml.NewEncoder(f)
	enc.Indent("", "  ")
	if err := enc.Encode(data); err != nil {
		panic(err)
	}
	fmt.Printf("Created %s\n", path)
}
