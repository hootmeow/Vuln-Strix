package reporting

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/smtp"
	"path/filepath"
	"time"

	"github.com/hootmeow/Vuln-Strix/internal/config"
	"github.com/hootmeow/Vuln-Strix/internal/storage"
)

type Mailer struct {
	Config config.EmailConfig
	Store  storage.Store
}

func NewMailer(cfg config.EmailConfig, store storage.Store) *Mailer {
	return &Mailer{
		Config: cfg,
		Store:  store,
	}
}

func (m *Mailer) SendDeltaReport() error {
	if !m.Config.Enabled {
		return fmt.Errorf("email reporting is disabled")
	}

	// 1. Gather Data
	// For simplicity, we'll use placeholder data for now as exact delta logic
	// requires complex historical queries not fully implemented efficiently yet.
	// But we can pull the Aging Cohorts we made!

	cohorts, err := m.Store.GetAgingCohorts()
	if err != nil {
		log.Printf("Error getting cohorts for report: %v", err)
		// Continue with empty?
	}

	// Fetch actual recently fixed findings for the report
	fixedFindings, err := m.Store.GetFixedFindings(7) // Last 7 days
	if err != nil {
		log.Printf("Error getting fixed findings: %v", err)
	}

	data := struct {
		Date          string
		NewRisk       int
		FixedRisk     int
		Cohorts       map[string]int64
		FixedFindings []storage.FindingSummary
	}{
		Date:          time.Now().Format("2006-01-02"),
		NewRisk:       15, // Mock
		FixedRisk:     len(fixedFindings),
		Cohorts:       cohorts,
		FixedFindings: fixedFindings,
	}

	// 2. Render Template
	// Assuming templates are in ./internal/server/templates relative to execution or fixed path
	// We'll try to find it.
	tmplPath := filepath.Join("internal", "server", "templates", "report_delta.html")

	// Helper function for subtraction in template
	funcMap := template.FuncMap{
		"sub": func(a, b int) int { return a - b },
	}

	tmpl, err := template.New("report_delta.html").Funcs(funcMap).ParseFiles(tmplPath)
	if err != nil {
		return fmt.Errorf("failed to parse report template: %w", err)
	}

	var body bytes.Buffer
	// Email Headers (MIME)
	headers := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	body.WriteString(fmt.Sprintf("Subject: Vuln-Strix Weekly Risk Report - %s\n%s", data.Date, headers))

	if err := tmpl.ExecuteTemplate(&body, "content", data); err != nil {
		return fmt.Errorf("failed to render report template: %w", err)
	}

	// 3. Send Email
	auth := smtp.PlainAuth("", m.Config.Username, m.Config.Password, m.Config.SMTPServer)
	addr := fmt.Sprintf("%s:%d", m.Config.SMTPServer, m.Config.SMTPPort)

	log.Printf("Sending email to %v via %s...", m.Config.ToAddr, addr)
	err = smtp.SendMail(addr, auth, m.Config.FromAddr, m.Config.ToAddr, body.Bytes())
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Println("Weekly report sent successfully.")
	return nil
}
