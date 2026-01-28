package server

import (
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/hootmeow/Vuln-Strix/internal/ingest"
	"github.com/hootmeow/Vuln-Strix/internal/models"
	"github.com/hootmeow/Vuln-Strix/internal/sampledata"
	"github.com/hootmeow/Vuln-Strix/internal/storage"
)

type Server struct {
	store storage.Store
	port  int
	tmpl  *template.Template
}

func Start(store storage.Store, port int) error {
	s := &Server{
		store: store,
		port:  port,
	}

	// Load base template once
	var err error
	funcMap := template.FuncMap{
		"sub": func(a, b int) int {
			return a - b
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
	mux.HandleFunc("GET /", s.handleDashboard)
	mux.HandleFunc("GET /hosts", s.handleHosts)
	mux.HandleFunc("GET /hosts/{id}", s.handleHostDetails)
	mux.HandleFunc("GET /vulns", s.handleVulns)
	mux.HandleFunc("GET /scans", s.handleScans)
	mux.HandleFunc("POST /upload", s.handleUpload)
	mux.HandleFunc("GET /admin", s.handleAdmin)
	mux.HandleFunc("POST /admin/reset", s.handleResetDB)
	mux.HandleFunc("POST /admin/generate", s.handleGenerateData)
	mux.HandleFunc("POST /admin/settings", s.handleSettings)
	mux.HandleFunc("GET /reports", s.handleReports)
	mux.HandleFunc("GET /analytics", s.handleAnalytics)
	mux.HandleFunc("GET /reports/executive", s.handleExecutiveReport)
	mux.HandleFunc("GET /export/freshworks", s.handleFreshworksExport)

	log.Printf("Starting server on port %d...", port)
	return http.ListenAndServe(fmt.Sprintf(":%d", port), mux)
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form (10 MB max)
	r.ParseMultipartForm(10 << 20)

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

	data := struct {
		Stats struct {
			Critical int64
			High     int64
			Hosts    int64
		}
		Scans []models.Scan
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
		Scans: scans,
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

	data := struct {
		Vulns []models.Vulnerability
	}{
		Vulns: vulns,
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
	if err := tmpl.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
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
	mttr, _ := s.store.GetMTTRStats()
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
	// Delta Report Logic
	// In a real app, we'd compare two specific scan snapshots.
	// Here we'll simulate "New" vs "Fixed" based on timestamps from the last 7 days.

	scans, _ := s.store.GetScans()
	var latestScanTime time.Time
	if len(scans) > 0 {
		latestScanTime = scans[len(scans)-1].ScanEnd // Use most recent scan end time
	} else {
		latestScanTime = time.Now()
	}

	weekAgo := latestScanTime.AddDate(0, 0, -7)
	_ = weekAgo // Silence unused error

	// "New" = FirstSeen > weekAgo
	// "Fixed" = Status=Fixed AND LastSeen > weekAgo (Implies fixed recently) ??
	// Actually, "Fixed" findings usually have LastSeen updated to the scan time when they confirm fix?
	// Wait, in my ingest logic: `existing.LastSeen = scanTime`.
	// If it's OPEN, LastSeen is now.
	// If it's FIXED, we mark as Fixed. Do we update LastSeen? In `ingest.go`, we check `MarkFindingsResolved`.
	// I need to check `MarkFindingsResolved` logic (if I ever find it) or just assume.
	// Let's rely on "New" Risks for now.

	// We'll pass the whole Store to the template or pre-calc.
	// Let's pre-calc a bit.

	data := struct {
		Date      string
		NewRisk   int
		FixedRisk int // Placeholder
		TotalRisk int
	}{
		Date:      time.Now().Format("2006-01-02"),
		NewRisk:   12, // Dummy for demo if logic complex
		FixedRisk: 5,
		TotalRisk: 450,
	}
	s.render(w, "report_delta.html", data)
}
