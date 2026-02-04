package ingest

import (
	"encoding/xml"
)

type NessusClientData_v2 struct {
	XMLName xml.Name `xml:"NessusClientData_v2"`
	Report  Report   `xml:"Report"`
	Policy  Policy   `xml:"Policy"`
}

type Policy struct {
	PolicyName  string      `xml:"policyName"`
	Preferences Preferences `xml:"Preferences"`
}

type Preferences struct {
	ServerPreferences []Preference `xml:"ServerPreferences>preference"`
	// OR sometimes standard preferences
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
	Severity     string `xml:"severity,attr"` // Nessus uses 0-4
	SvcName      string `xml:"svc_name,attr"`

	Description string   `xml:"description"`
	Solution    string   `xml:"solution,omitempty"`
	RiskFactor  string   `xml:"risk_factor,omitempty"`
	CVE         []string `xml:"cve"`
	Xref        []string `xml:"xref"`
}

// Helper to get Tag value
func (hp *HostProperties) Get(name string) string {
	for _, t := range hp.Tag {
		if t.Name == name {
			return t.Text
		}
	}
	return ""
}
