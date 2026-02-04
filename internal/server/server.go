package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/hootmeow/Vuln-Strix/internal/auth"
	"github.com/hootmeow/Vuln-Strix/internal/config"
	"github.com/hootmeow/Vuln-Strix/internal/ingest"
	"github.com/hootmeow/Vuln-Strix/internal/models"
	"github.com/hootmeow/Vuln-Strix/internal/sampledata"
	"github.com/hootmeow/Vuln-Strix/internal/storage"
)

type Server struct {
	store      storage.Store
	cfg        *config.Config
	tmpl       *template.Template
	sessions   *auth.SessionManager
	ldapAuth   *auth.LDAPAuthenticator
}

func Start(store storage.Store, cfg *config.Config) error {
	s := &Server{
		store: store,
		cfg:   cfg,
	}

	// Initialize auth if enabled
	if cfg.Auth.Enabled {
		s.sessions = auth.NewSessionManager(cfg.Auth.SessionMinutes)
		s.ldapAuth = auth.NewLDAPAuthenticator(
			cfg.Auth.LDAPServer,
			cfg.Auth.LDAPPort,
			cfg.Auth.UseTLS,
			cfg.Auth.BaseDN,
			cfg.Auth.BindUser,
			cfg.Auth.BindPassword,
			cfg.Auth.UserFilter,
		)
	}

	// Load base template once
	var err error
	funcMap := template.FuncMap{
		"sub": func(a, b int) int {
			return a - b
		},
		"add": func(a, b int) int {
			return a + b
		},
		"json": func(v interface{}) template.JS {
			a, _ := json.Marshal(v)
			return template.JS(a)
		},
	}

	// We must parse the base template with the FuncMap attached.
	// However, ParseGlob creates a new template. We need New().Funcs().ParseGlob()
	s.tmpl = template.New("").Funcs(funcMap)

	// Try standard path
	basePath := "internal/server/templates/base.html"
	_, err = s.tmpl.ParseGlob(basePath)
	if err != nil {
		// Fallback path
		basePath = "../../internal/server/templates/base.html"
		_, err = s.tmpl.ParseGlob(basePath)
		if err != nil {
			return fmt.Errorf("could not load base template: %w", err)
		}
	}

	// Use Go 1.22 enhanced routing
	mux := http.NewServeMux()

	// Static file server (not protected by auth)
	staticPath := "static"
	if _, err := os.Stat(staticPath); os.IsNotExist(err) {
		staticPath = "../../static"
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticPath))))

	// Auth routes (not protected)
	if cfg.Auth.Enabled {
		mux.HandleFunc("GET /login", s.handleLoginPage)
		mux.HandleFunc("POST /login", s.handleLogin)
		mux.HandleFunc("GET /logout", s.handleLogout)
	}

	// Protected routes
	mux.HandleFunc("GET /", s.handleDashboard)
	mux.HandleFunc("GET /hosts", s.handleHosts)
	mux.HandleFunc("GET /hosts/{id}", s.handleHostDetails)
	mux.HandleFunc("GET /vulns", s.handleVulns)
	mux.HandleFunc("GET /scans", s.handleScans)
	mux.HandleFunc("GET /scans/diff", s.handleScanDiff)
	mux.HandleFunc("POST /upload", s.handleUpload)
	mux.HandleFunc("GET /admin", s.handleAdmin)
	mux.HandleFunc("POST /admin/reset", s.handleResetDB)
	mux.HandleFunc("POST /admin/generate", s.handleGenerateData)
	mux.HandleFunc("POST /admin/settings", s.handleSettings)
	mux.HandleFunc("GET /reports", s.handleReports)
	mux.HandleFunc("GET /analytics", s.handleAnalytics)
	mux.HandleFunc("GET /reports/executive", s.handleExecutiveReport)
	mux.HandleFunc("GET /export/freshworks", s.handleFreshworksExport)
	mux.HandleFunc("GET /export/findings", s.handleFindingsExport)

	// API / Action Routes (Batch 3)
	mux.HandleFunc("POST /api/hosts/{id}/tags", s.handleAddTag)
	mux.HandleFunc("DELETE /api/hosts/{id}/tags/{tag}", s.handleRemoveTag)
	mux.HandleFunc("POST /api/findings/{id}/snooze", s.handleSnooze)
	mux.HandleFunc("POST /api/findings/{id}/resolve", s.handleResolve)
	mux.HandleFunc("POST /api/vulns/{id}/runbook", s.handleUpdateRunbook)

	// Wrap with auth middleware if enabled
	var handler http.Handler = mux
	if cfg.Auth.Enabled {
		handler = s.authMiddleware(mux)
	}

	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	if cfg.TLS.Enabled {
		log.Printf("Starting HTTPS server on port %d...", cfg.Server.Port)
		return http.ListenAndServeTLS(addr, cfg.TLS.CertFile, cfg.TLS.KeyFile, handler)
	}

	log.Printf("Starting HTTP server on port %d...", cfg.Server.Port)
	return http.ListenAndServe(addr, handler)
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form (200 MB max)
	r.ParseMultipartForm(200 << 20)

	file, header, err := r.FormFile("scanfile")
	if err != nil {
		http.Error(w, "Invalid file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Save to temp file
	tempDir := os.TempDir()
	tempPath := filepath.Join(tempDir, header.Filename)

	outFile, err := os.Create(tempPath)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	_, err = io.Copy(outFile, file)
	outFile.Close()
	if err != nil {
		http.Error(w, "Failed to write file", http.StatusInternalServerError)
		return
	}

	// Ingest
	go func() {
		defer os.Remove(tempPath)
		if err := ingest.ProcessFile(s.store, tempPath); err != nil {
			log.Printf("Upload Ingestion Error: %v", err)
		}
	}()

	// Redirect back to dashboard
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	crit, _ := s.store.GetVulnCount("Critical")
	high, _ := s.store.GetVulnCount("High")
	totalHosts, _ := s.store.GetHostCount()

	// Fetch scans for trend chart
	scans, err := s.store.GetScans()
	if err != nil {
		log.Printf("Failed to fetch scans for dashboard: %v", err)
	}

	// Fetch Family Stats (Last 90 days)
	familyStats, _ := s.store.GetFamilyStats(90)

	data := struct {
		Stats struct {
			Critical int64
			High     int64
			Hosts    int64
		}
		Scans       []models.Scan
		FamilyStats map[string]int
	}{
		Stats: struct {
			Critical int64
			High     int64
			Hosts    int64
		}{
			Critical: crit,
			High:     high,
			Hosts:    totalHosts,
		},
		Scans:       scans,
		FamilyStats: familyStats,
	}

	s.render(w, "dashboard.html", data)
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.store.GetHosts()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Hosts []models.Host
	}{
		Hosts: hosts,
	}

	s.render(w, "hosts.html", data)
}

func (s *Server) handleHostDetails(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	var id uint
	fmt.Sscanf(idStr, "%d", &id)

	host, err := s.store.GetHost(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	findings, err := s.store.GetFindingsForHost(id)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Host     *models.Host
		Findings []models.Finding
	}{
		Host:     host,
		Findings: findings,
	}

	s.render(w, "host_details.html", data)
}

func (s *Server) handleVulns(w http.ResponseWriter, r *http.Request) {
	vulns, err := s.store.GetVulnerabilities()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Group by Family
	groupedMap := make(map[string][]models.Vulnerability)
	for _, v := range vulns {
		if v.Family == "" {
			v.Family = "Uncategorized"
		}
		groupedMap[v.Family] = append(groupedMap[v.Family], v)
	}

	// Convert to sorted slice for consistent ordering
	type VulnFamilyGroup struct {
		Name  string
		Vulns []models.Vulnerability
	}
	var groupedVulns []VulnFamilyGroup
	for name, vs := range groupedMap {
		groupedVulns = append(groupedVulns, VulnFamilyGroup{Name: name, Vulns: vs})
	}
	sort.Slice(groupedVulns, func(i, j int) bool {
		return groupedVulns[i].Name < groupedVulns[j].Name
	})

	data := struct {
		Vulns        []models.Vulnerability
		GroupedVulns []VulnFamilyGroup
	}{
		Vulns:        vulns,
		GroupedVulns: groupedVulns,
	}

	s.render(w, "vulns.html", data)
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.store.GetScans()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Scans []models.Scan
	}{
		Scans: scans,
	}

	s.render(w, "scans.html", data)
}

func (s *Server) render(w http.ResponseWriter, pageName string, data interface{}) {
	// Clone the base template
	tmpl, err := s.tmpl.Clone()
	if err != nil {
		log.Printf("Template clone error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Parse the specific page
	// We need to resolve the path again.
	// NOTE: This assumes templates are in the same dir as base.html
	// Since we used ParseGlob before, we need to know the specific path.
	// Let's rely on the base path logic used in Start.

	// Quick fix: Determine path prefix capability
	var pathPrefix string
	if _, err := os.Stat("internal/server/templates/base.html"); err == nil {
		pathPrefix = "internal/server/templates/"
	} else {
		pathPrefix = "../../internal/server/templates/"
	}

	_, err = tmpl.ParseFiles(filepath.Join(pathPrefix, pageName))
	if err != nil {
		log.Printf("Template parse error (%s): %v", pageName, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Execute "base.html" which should include the "content" block defined in pageName
	// BUT: "base.html" is the name of the file. The template name defined inside might be different?
	// Actually, ParseGlob/Files uses the filename (basename) as the template name.
	// Execute to a buffer first to catch errors before writing to the response
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "base.html", data); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Successful execution, write buffer to response
	buf.WriteTo(w)
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	sla := s.store.GetSLAConfig()
	data := struct {
		SLA map[string]int
	}{
		SLA: sla,
	}
	s.render(w, "admin.html", data)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	for _, sev := range []string{"Critical", "High", "Medium", "Low"} {
		key := "sla_" + sev
		val := r.FormValue(key)
		if val != "" {
			if err := s.store.UpdateSetting(key, val); err != nil {
				log.Printf("Failed to update setting %s: %v", key, err)
			}
		}
	}

	http.Redirect(w, r, "/admin?status=settings_saved", http.StatusSeeOther)
}

func (s *Server) handleResetDB(w http.ResponseWriter, r *http.Request) {
	if err := s.store.ResetDB(); err != nil {
		log.Printf("Failed to reset DB: %v", err)
		http.Error(w, "Failed to reset database", http.StatusInternalServerError)
		return
	}

	// Re-run migrations to recreate tables
	if err := s.store.AutoMigrate(); err != nil {
		log.Printf("Failed to migrate after reset: %v", err)
		http.Error(w, "Failed to migrate database", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin?status=reset_success", http.StatusSeeOther)
}

func (s *Server) handleGenerateData(w http.ResponseWriter, r *http.Request) {
	// Generate data to "samples" dir
	sampleDir := "samples"
	if err := sampledata.Generate(sampleDir); err != nil {
		log.Printf("Failed to generate sample data: %v", err)
		http.Error(w, "Failed to generate data", http.StatusInternalServerError)
		return
	}

	// Ingest files
	files, err := filepath.Glob(filepath.Join(sampleDir, "*.nessus"))
	if err != nil {
		log.Printf("Failed to glob sample files: %v", err)
		http.Error(w, "Failed to find sample files", http.StatusInternalServerError)
		return
	}

	for _, f := range files {
		if err := ingest.ProcessFile(s.store, f); err != nil {
			log.Printf("Failed to ingest sample file %s: %v", f, err)
			// Continue with others
		}
	}

	http.Redirect(w, r, "/admin?status=generate_success", http.StatusSeeOther)
}

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	// For advanced reporting, we want to calculate:
	// 1. Total findings over time (already on dashboard, but maybe more granular)
	// 2. Scan Delta: Comparing the last two scans globally

	scans, err := s.store.GetScans()
	if err != nil || len(scans) < 2 {
		data := struct {
			CanCompare bool
			Message    string
		}{
			CanCompare: false,
			Message:    "At least two scans are required for comparison reports.",
		}
		s.render(w, "reports.html", data)
		return
	}

	// Simple Delta calculation between latest and previous
	latest := scans[0]
	prev := scans[1]

	aging, _ := s.store.GetAgingStats()
	mttr, _ := s.store.GetMTTRStats(90)
	slaBreaches, _ := s.store.GetSLACompliance()

	data := struct {
		CanCompare  bool
		Latest      models.Scan
		Previous    models.Scan
		Aging       map[string]int
		MTTR        map[string]float64
		SLABreaches []models.Finding
		Message     string
	}{
		CanCompare:  true,
		Latest:      latest,
		Previous:    prev,
		Aging:       aging,
		MTTR:        mttr,
		SLABreaches: slaBreaches,
	}

	s.render(w, "reports.html", data)
}

func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	ghosts, _ := s.store.GetGhostHosts(30) // Default 30 days
	zombies, _ := s.store.GetZombieFindings()
	cohorts, _ := s.store.GetAgingCohorts()

	data := struct {
		Ghosts  []models.Host
		Zombies []models.Finding
		Cohorts map[string]int64
	}{
		Ghosts:  ghosts,
		Zombies: zombies,
		Cohorts: cohorts,
	}
	s.render(w, "analytics.html", data)
}

func (s *Server) handleFreshworksExport(w http.ResponseWriter, r *http.Request) {
	// Export Critical Findings
	findings, err := s.store.GetCriticalFindings()
	if err != nil {
		http.Error(w, "Error fetching data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment;filename=freshworks_criticals.csv")

	// Header
	fmt.Fprintln(w, "Summary,Description,Priority,Status,Asset")
	for _, f := range findings {
		summary := fmt.Sprintf("[%s] %s", f.Vuln.Severity, f.Vuln.Name)
		desc := fmt.Sprintf("Plugin: %s\nHost: %s (%s)\nPort: %d\n\n%s", f.Vuln.PluginID, f.Host.Hostname, f.Host.IP, f.Port, f.Vuln.Description)

		// Priority is always urgent for this export
		priority := "Urgent"

		fmt.Fprintf(w, "%q,%q,%s,Open,%s\n", summary, desc, priority, f.Host.Hostname)
	}
}

func (s *Server) handleExecutiveReport(w http.ResponseWriter, r *http.Request) {
	// Parse Time Range (default 7 days)
	daysStr := r.URL.Query().Get("days")
	days := 7
	if daysStr != "" {
		fmt.Sscanf(daysStr, "%d", &days)
	}
	if days <= 0 {
		days = 7
	}

	// Fetch Stats based on Range
	fixedFindings, err := s.store.GetFixedFindings(days)
	if err != nil {
		log.Printf("Error getting fixed findings: %v", err)
	}

	newFindings, err := s.store.GetNewFindings(days)
	if err != nil {
		log.Printf("Error getting new findings: %v", err)
	}

	mttrStats, err := s.store.GetMTTRStats(days)
	if err != nil {
		log.Printf("Error getting MTTR: %v", err)
	}
	// Calculate avg MTTR for Critical
	mttrVal := mttrStats["Critical"]

	slaBreaches, err := s.store.GetSLACompliance()
	if err != nil {
		log.Printf("Error getting SLA compliance: %v", err)
	}
	// Simple compliance %:  1 - (AssetsWithBreaches / TotalAssets)
	// For now, let's just use Breach Count if we don't have easy TotalAssets map
	// Or better: Store.GetSLACompliance returns breaches.
	// Let's get Total Host Count.
	hostCount, _ := s.store.GetHostCount()
	slaCompliance := 100.0
	if hostCount > 0 {
		// Count unique hosts in breaches
		uniqueBreachHosts := make(map[uint]bool)
		for _, b := range slaBreaches {
			uniqueBreachHosts[b.HostID] = true
		}
		slaCompliance = 100.0 * (1.0 - float64(len(uniqueBreachHosts))/float64(hostCount))
	}

	var criticalNew []models.Finding
	for _, f := range newFindings {
		if f.Vuln.Severity == "Critical" || f.Vuln.Severity == "High" {
			criticalNew = append(criticalNew, f)
		}
	}

	topRisky, err := s.store.GetTopRiskyHosts(5)
	if err != nil {
		log.Printf("Error getting top risky hosts: %v", err)
	}

	// Calculate Total Risk (Simple Heuristic for now based on New Findings)
	// In a real scenario, this might be the Total Risk of the entire infrastructure.
	// Let's assume the user wants "Risk Added" vs "Risk Removed" since this is a Delta report.
	// But the card says "Net Risk Change", implying the delta.
	// The "Cyber Hygiene Score" uses NewRisk count.
	// Let's make TotalRisk represent the *weighted* risk of the new findings.
	totalRiskScore := 0.0
	for _, f := range newFindings {
		switch f.Vuln.Severity {
		case "Critical":
			totalRiskScore += 10
		case "High":
			totalRiskScore += 5
		case "Medium":
			totalRiskScore += 1
		case "Low":
			totalRiskScore += 0.1
		}
	}

	data := struct {
		Date          string
		Days          int
		NewRisk       int
		FixedRisk     int
		TotalRisk     int
		FixedFindings []storage.FindingSummary
		NewFindings   []models.Finding
		TopRisky      []storage.HostRiskSummary
		MTTR          string
		SLA           string
	}{
		Date:          time.Now().Format("Jan 02, 2006"),
		Days:          days,
		NewRisk:       len(newFindings),
		FixedRisk:     len(fixedFindings),
		TotalRisk:     int(totalRiskScore),
		FixedFindings: fixedFindings,
		NewFindings:   criticalNew,
		TopRisky:      topRisky,
		MTTR:          fmt.Sprintf("%.1fd", mttrVal),
		SLA:           fmt.Sprintf("%.0f%%", slaCompliance),
	}

	s.render(w, "report_delta.html", data)
}

// Batch 3 Handlers

func (s *Server) handleAddTag(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	var id uint
	fmt.Sscanf(idStr, "%d", &id)

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	tagName := r.FormValue("name")
	color := r.FormValue("color")

	if err := s.store.AddHostTag(id, tagName, color); err != nil {
		log.Printf("Error adding tag: %v", err)
		http.Error(w, "Failed to add tag", http.StatusInternalServerError)
		return
	}
	// Return success or redirect
	// For AJAX, usually JSON. For simplification, we just redirect or 200.
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" || r.Header.Get("Accept") == "application/json" {
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/hosts/%d", id), http.StatusSeeOther)
}

func (s *Server) handleRemoveTag(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	var id uint
	fmt.Sscanf(idStr, "%d", &id)
	tagName := r.PathValue("tag")

	if err := s.store.RemoveHostTag(id, tagName); err != nil {
		http.Error(w, "Failed to remove tag", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleSnooze(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	var id uint
	fmt.Sscanf(idStr, "%d", &id)

	r.ParseForm()
	daysStr := r.FormValue("days")
	reason := r.FormValue("reason")
	log.Printf("Snooze request: id=%d, days=%s, reason=%s", id, daysStr, reason)
	var days int
	fmt.Sscanf(daysStr, "%d", &days)

	if err := s.store.SnoozeFinding(id, days, reason); err != nil {
		http.Error(w, "Failed to snooze finding", http.StatusInternalServerError)
		return
	}
	// Redirect back to host details or return JSON
	// Since this is likely from a modal, we redirect or reload.
	// We need the Host ID to redirect back to. But we only have finding ID.
	// We can lookup finding to get Host ID, OR just return 200 for JS reload.
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleUpdateRunbook(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	var id uint
	fmt.Sscanf(idStr, "%d", &id)

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	url := r.FormValue("url")

	if err := s.store.UpdateRunbook(id, url); err != nil {
		http.Error(w, "Failed to update runbook", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/vulns", http.StatusSeeOther)
}

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	var id uint
	fmt.Sscanf(idStr, "%d", &id)

	r.ParseForm()
	note := r.FormValue("note")
	log.Printf("Resolve request: id=%d, note=%s", id, note)

	if err := s.store.ResolveFinding(id, note); err != nil {
		http.Error(w, "Failed to resolve finding", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleScanDiff(w http.ResponseWriter, r *http.Request) {
	baseIDStr := r.URL.Query().Get("base")
	targetIDStr := r.URL.Query().Get("target")

	var baseID, targetID uint
	fmt.Sscanf(baseIDStr, "%d", &baseID)
	fmt.Sscanf(targetIDStr, "%d", &targetID)

	// If IDs missing, just pick the last two scans if available
	if baseID == 0 || targetID == 0 {
		scans, err := s.store.GetScans()
		if err == nil && len(scans) >= 2 {
			// Sort by date usually? GetScans might not be sorted.
			// Assuming latest first or last... usually GetScans is ID desc or asc.
			// Let's assume Scan ID increases with time.
			// Target = Latest (highest ID), Base = Previous.
			// If not provided, we show error or selector page?
			// Let's redirect to scans page with error if not provided?
			// Or auto-select for demo.
			if len(scans) >= 2 {
				targetID = scans[len(scans)-1].ID
				baseID = scans[len(scans)-2].ID
			}
		}
	}

	if baseID == 0 || targetID == 0 {
		http.Error(w, "Select two scans to compare", http.StatusBadRequest)
		return
	}

	diff, err := s.store.GetScanDiff(baseID, targetID)
	if err != nil {
		log.Printf("Diff error: %v", err)
		http.Error(w, "Error calculating diff", http.StatusInternalServerError)
		return
	}

	s.render(w, "scan_diff.html", diff)
}

func (s *Server) handleFindingsExport(w http.ResponseWriter, r *http.Request) {
	hostIDStr := r.URL.Query().Get("host_id")
	var hostID uint
	if hostIDStr != "" {
		fmt.Sscanf(hostIDStr, "%d", &hostID)
	}

	findings, err := s.store.GetFindingsForExport(hostID)
	if err != nil {
		http.Error(w, "Failed to fetch findings", http.StatusInternalServerError)
		return
	}

	filename := "vuln_strix_export.csv"
	if hostID > 0 && len(findings) > 0 {
		filename = fmt.Sprintf("vuln_strix_host_%d_export.csv", hostID)
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))

	// Write BOM for Excel compatibility
	w.Write([]byte{0xEF, 0xBB, 0xBF})

	// CSV Header
	fmt.Fprintln(w, "Hostname,IP,OS,Vulnerability,Family,Severity,Status,Solution,FirstSeen,LastSeen,Notes")

	for _, f := range findings {
		// Clean description/solution for CSV (replace newlines/commas if needed, but simple quoting works mostly)
		// Using fmt.Sprintf("%q") helps quote strings safely
		line := fmt.Sprintf("%q,%q,%q,%q,%q,%q,%q,%q,%s,%s,%q",
			f.Host.Hostname,
			f.Host.IP,
			f.Host.OS,
			f.Vuln.Name,
			f.Vuln.Family,
			f.Vuln.Severity,
			f.Status,
			f.Vuln.Solution,
			f.FirstSeen.Format("2006-01-02"),
			f.LastSeen.Format("2006-01-02"),
			f.ResolutionNote,
		)
		fmt.Fprintln(w, line)
	}
}

// Auth Middleware
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for static files and auth routes
		if r.URL.Path == "/login" || r.URL.Path == "/logout" ||
			len(r.URL.Path) > 7 && r.URL.Path[:8] == "/static/" {
			next.ServeHTTP(w, r)
			return
		}

		// Check for valid session
		cookie, err := r.Cookie("vs_session")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		session, ok := s.sessions.Get(cookie.Value)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Store session in request context
		r = auth.SetSessionContext(r, session)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	errorMsg := r.URL.Query().Get("error")
	data := struct {
		Error string
	}{
		Error: errorMsg,
	}
	s.render(w, "login.html", data)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/login?error=Invalid+form+data", http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		http.Redirect(w, r, "/login?error=Username+and+password+required", http.StatusSeeOther)
		return
	}

	// Authenticate against LDAP
	user, err := s.ldapAuth.Authenticate(username, password)
	if err != nil {
		log.Printf("LDAP auth failed for user %s: %v", username, err)
		http.Redirect(w, r, "/login?error=Invalid+credentials", http.StatusSeeOther)
		return
	}

	// Create session
	sessionID := s.sessions.Create(user)

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "vs_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLS.Enabled,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("vs_session")
	if err == nil && cookie.Value != "" {
		s.sessions.Delete(cookie.Value)
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "vs_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// GetCurrentUser returns the current user from request context, or nil if no auth
func (s *Server) getCurrentUser(r *http.Request) *auth.User {
	if !s.cfg.Auth.Enabled {
		return nil
	}
	session := auth.GetSessionContext(r)
	if session == nil {
		return nil
	}
	return session.User
}
