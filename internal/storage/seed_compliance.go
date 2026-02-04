package storage

import (
	"log"

	"github.com/hootmeow/Vuln-Strix/internal/models"
)

// SeedComplianceFrameworks creates default compliance frameworks and controls.
func (s *SQLiteStore) SeedComplianceFrameworks() error {
	frameworks := []struct {
		Framework models.ComplianceFramework
		Controls  []models.ComplianceControl
	}{
		{
			Framework: models.ComplianceFramework{
				Code:        "PCI-DSS",
				Name:        "Payment Card Industry Data Security Standard",
				Version:     "4.0",
				Description: "Security standard for organizations that handle credit cards",
				Color:       "#0d6efd",
			},
			Controls: []models.ComplianceControl{
				{ControlID: "1.1", Title: "Install and maintain network security controls", Priority: 1},
				{ControlID: "1.2", Title: "Configure network security controls", Priority: 1},
				{ControlID: "2.1", Title: "Apply secure configurations to system components", Priority: 1},
				{ControlID: "2.2", Title: "Manage default accounts and passwords", Priority: 1},
				{ControlID: "3.1", Title: "Processes for protecting stored account data", Priority: 1},
				{ControlID: "3.2", Title: "Protect stored account data", Priority: 1},
				{ControlID: "4.1", Title: "Protect cardholder data during transmission", Priority: 1},
				{ControlID: "5.1", Title: "Protect systems against malware", Priority: 1},
				{ControlID: "5.2", Title: "Anti-malware mechanisms are active", Priority: 1},
				{ControlID: "6.1", Title: "Identify and address security vulnerabilities", Priority: 1},
				{ControlID: "6.2", Title: "Develop software securely", Priority: 1},
				{ControlID: "6.3", Title: "Protect web applications", Priority: 1},
				{ControlID: "7.1", Title: "Restrict access by business need-to-know", Priority: 2},
				{ControlID: "7.2", Title: "Appropriate access control systems", Priority: 2},
				{ControlID: "8.1", Title: "Identify users and authenticate access", Priority: 1},
				{ControlID: "8.2", Title: "Strong authentication for users and administrators", Priority: 1},
				{ControlID: "9.1", Title: "Restrict physical access to cardholder data", Priority: 2},
				{ControlID: "10.1", Title: "Log and monitor access to system components", Priority: 1},
				{ControlID: "10.2", Title: "Detect anomalies and suspicious activity", Priority: 1},
				{ControlID: "11.1", Title: "Test security systems and networks regularly", Priority: 1},
				{ControlID: "11.2", Title: "Scan for unauthorized wireless access points", Priority: 2},
				{ControlID: "11.3", Title: "External and internal vulnerability scans", Priority: 1},
				{ControlID: "11.4", Title: "Penetration testing", Priority: 1},
				{ControlID: "12.1", Title: "Information security policy", Priority: 2},
			},
		},
		{
			Framework: models.ComplianceFramework{
				Code:        "HIPAA",
				Name:        "Health Insurance Portability and Accountability Act",
				Version:     "2013",
				Description: "US regulation for medical information protection",
				Color:       "#198754",
			},
			Controls: []models.ComplianceControl{
				{ControlID: "164.308(a)(1)", Title: "Security Management Process", Priority: 1},
				{ControlID: "164.308(a)(2)", Title: "Assigned Security Responsibility", Priority: 2},
				{ControlID: "164.308(a)(3)", Title: "Workforce Security", Priority: 1},
				{ControlID: "164.308(a)(4)", Title: "Information Access Management", Priority: 1},
				{ControlID: "164.308(a)(5)", Title: "Security Awareness and Training", Priority: 2},
				{ControlID: "164.308(a)(6)", Title: "Security Incident Procedures", Priority: 1},
				{ControlID: "164.308(a)(7)", Title: "Contingency Plan", Priority: 2},
				{ControlID: "164.308(a)(8)", Title: "Evaluation", Priority: 2},
				{ControlID: "164.310(a)(1)", Title: "Facility Access Controls", Priority: 2},
				{ControlID: "164.310(b)", Title: "Workstation Use", Priority: 2},
				{ControlID: "164.310(c)", Title: "Workstation Security", Priority: 2},
				{ControlID: "164.310(d)(1)", Title: "Device and Media Controls", Priority: 1},
				{ControlID: "164.312(a)(1)", Title: "Access Control", Priority: 1},
				{ControlID: "164.312(b)", Title: "Audit Controls", Priority: 1},
				{ControlID: "164.312(c)(1)", Title: "Integrity", Priority: 1},
				{ControlID: "164.312(d)", Title: "Person or Entity Authentication", Priority: 1},
				{ControlID: "164.312(e)(1)", Title: "Transmission Security", Priority: 1},
			},
		},
		{
			Framework: models.ComplianceFramework{
				Code:        "NIST-CSF",
				Name:        "NIST Cybersecurity Framework",
				Version:     "2.0",
				Description: "Voluntary framework for improving critical infrastructure cybersecurity",
				Color:       "#6f42c1",
			},
			Controls: []models.ComplianceControl{
				{ControlID: "ID.AM-1", Title: "Physical devices and systems are inventoried", Priority: 2},
				{ControlID: "ID.AM-2", Title: "Software platforms and applications are inventoried", Priority: 2},
				{ControlID: "ID.RA-1", Title: "Asset vulnerabilities are identified and documented", Priority: 1},
				{ControlID: "ID.RA-2", Title: "Threat intelligence is received from information sharing forums", Priority: 2},
				{ControlID: "ID.RA-5", Title: "Threats, vulnerabilities, likelihoods, and impacts are used to determine risk", Priority: 1},
				{ControlID: "PR.AC-1", Title: "Identities and credentials are managed", Priority: 1},
				{ControlID: "PR.AC-3", Title: "Remote access is managed", Priority: 1},
				{ControlID: "PR.AC-4", Title: "Access permissions are managed", Priority: 1},
				{ControlID: "PR.AC-5", Title: "Network integrity is protected", Priority: 1},
				{ControlID: "PR.DS-1", Title: "Data-at-rest is protected", Priority: 1},
				{ControlID: "PR.DS-2", Title: "Data-in-transit is protected", Priority: 1},
				{ControlID: "PR.IP-1", Title: "Baseline configuration is created and maintained", Priority: 1},
				{ControlID: "PR.IP-12", Title: "Vulnerability management plan is developed and implemented", Priority: 1},
				{ControlID: "PR.PT-1", Title: "Audit/log records are determined and documented", Priority: 1},
				{ControlID: "DE.AE-1", Title: "Network operations baseline is established", Priority: 2},
				{ControlID: "DE.CM-1", Title: "Network is monitored for cybersecurity events", Priority: 1},
				{ControlID: "DE.CM-4", Title: "Malicious code is detected", Priority: 1},
				{ControlID: "DE.CM-8", Title: "Vulnerability scans are performed", Priority: 1},
				{ControlID: "RS.AN-1", Title: "Notifications from detection systems are investigated", Priority: 1},
				{ControlID: "RS.MI-3", Title: "Newly identified vulnerabilities are mitigated or documented", Priority: 1},
				{ControlID: "RC.RP-1", Title: "Recovery plan is executed", Priority: 2},
			},
		},
		{
			Framework: models.ComplianceFramework{
				Code:        "CIS",
				Name:        "CIS Critical Security Controls",
				Version:     "8.0",
				Description: "Prioritized set of actions to protect against cyber attacks",
				Color:       "#dc3545",
			},
			Controls: []models.ComplianceControl{
				{ControlID: "1.1", Title: "Establish and Maintain Detailed Enterprise Asset Inventory", Priority: 1},
				{ControlID: "1.2", Title: "Address Unauthorized Assets", Priority: 1},
				{ControlID: "2.1", Title: "Establish and Maintain a Software Inventory", Priority: 1},
				{ControlID: "2.2", Title: "Ensure Authorized Software is Currently Supported", Priority: 1},
				{ControlID: "2.3", Title: "Address Unauthorized Software", Priority: 1},
				{ControlID: "3.1", Title: "Establish and Maintain a Data Management Process", Priority: 2},
				{ControlID: "3.3", Title: "Configure Data Access Control Lists", Priority: 1},
				{ControlID: "4.1", Title: "Establish and Maintain a Secure Configuration Process", Priority: 1},
				{ControlID: "4.2", Title: "Establish and Maintain a Secure Configuration Process for Network Infrastructure", Priority: 1},
				{ControlID: "5.1", Title: "Establish and Maintain an Inventory of Accounts", Priority: 1},
				{ControlID: "5.2", Title: "Use Unique Passwords", Priority: 1},
				{ControlID: "5.3", Title: "Disable Dormant Accounts", Priority: 1},
				{ControlID: "6.1", Title: "Establish an Access Granting Process", Priority: 1},
				{ControlID: "6.2", Title: "Establish an Access Revoking Process", Priority: 1},
				{ControlID: "7.1", Title: "Establish and Maintain a Vulnerability Management Process", Priority: 1},
				{ControlID: "7.2", Title: "Establish and Maintain a Remediation Process", Priority: 1},
				{ControlID: "7.3", Title: "Perform Automated Operating System Patch Management", Priority: 1},
				{ControlID: "7.4", Title: "Perform Automated Application Patch Management", Priority: 1},
				{ControlID: "7.5", Title: "Perform Automated Vulnerability Scans of Internal Enterprise Assets", Priority: 1},
				{ControlID: "7.6", Title: "Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets", Priority: 1},
				{ControlID: "7.7", Title: "Remediate Detected Vulnerabilities", Priority: 1},
				{ControlID: "8.1", Title: "Establish and Maintain an Audit Log Management Process", Priority: 1},
				{ControlID: "8.2", Title: "Collect Audit Logs", Priority: 1},
				{ControlID: "10.1", Title: "Deploy and Maintain Anti-Malware Software", Priority: 1},
				{ControlID: "10.2", Title: "Configure Automatic Anti-Malware Signature Updates", Priority: 1},
				{ControlID: "13.1", Title: "Centralize Security Event Alerting", Priority: 1},
				{ControlID: "13.6", Title: "Collect Network Traffic Flow Logs", Priority: 2},
			},
		},
	}

	for _, fw := range frameworks {
		// Check if framework exists
		var existing models.ComplianceFramework
		result := s.db.Where("code = ?", fw.Framework.Code).First(&existing)
		if result.Error != nil {
			// Create framework
			if err := s.db.Create(&fw.Framework).Error; err != nil {
				log.Printf("Failed to seed framework %s: %v", fw.Framework.Code, err)
				continue
			}

			// Create controls
			for i := range fw.Controls {
				fw.Controls[i].FrameworkID = fw.Framework.ID
				if err := s.db.Create(&fw.Controls[i]).Error; err != nil {
					log.Printf("Failed to seed control %s: %v", fw.Controls[i].ControlID, err)
				}
			}
		}
	}

	log.Println("Compliance frameworks seeded")
	return nil
}
