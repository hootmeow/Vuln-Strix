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
	"strings"
	"time"

	"github.com/hootmeow/Vuln-Strix/internal/auth"
	"github.com/hootmeow/Vuln-Strix/internal/config"
	"github.com/hootmeow/Vuln-Strix/internal/ingest"
	"github.com/hootmeow/Vuln-Strix/internal/models"
	"github.com/hootmeow/Vuln-Strix/internal/sampledata"
	"github.com/hootmeow/Vuln-Strix/internal/storage"
)

type Breadcrumb struct {
	Text   string
	URL    string
	Active bool
}

type Server struct {
	store    storage.Store
	cfg      *config.Config
	tmpl     *template.Template
	sessions *auth.SessionManager
	ldapAuth *auth.LDAPAuthenticator
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
		"split": strings.Split,
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
	mux.HandleFunc("POST /admin/cleardata", s.handleClearData)
	mux.HandleFunc("GET /reports", s.handleReports)
	mux.HandleFunc("GET /analytics", s.handleAnalytics)
	mux.HandleFunc("GET /reports/executive", s.handleExecutiveReport)
	mux.HandleFunc("GET /export/freshworks", s.handleFreshworksExport)
	mux.HandleFunc("GET /export/findings", s.handleFindingsExport)

	// API / Action Routes (Batch 3)
	mux.HandleFunc("POST /api/hosts/{id}/tags", s.handleAddTag)
	mux.HandleFunc("POST /api/hosts/{id}/criticality", s.handleUpdateHostCriticality)
	mux.HandleFunc("GET /admin/audit", s.handleAuditLogs)
	mux.HandleFunc("DELETE /api/hosts/{id}/tags/{tag}", s.handleRemoveTag)
	mux.HandleFunc("POST /api/findings/{id}/snooze", s.handleSnooze)
	mux.HandleFunc("POST /api/findings/{id}/resolve", s.handleResolve)
	mux.HandleFunc("POST /api/vulns/{id}/runbook", s.handleUpdateRunbook)

	// Asset Groups
	mux.HandleFunc("GET /groups", s.handleGroups)
	mux.HandleFunc("GET /groups/{name}", s.handleGroupDetails)
	mux.HandleFunc("POST /api/groups", s.handleCreateGroup)
	mux.HandleFunc("PUT /api/groups/{id}", s.handleUpdateGroup)
	mux.HandleFunc("DELETE /api/groups/{id}", s.handleDeleteGroup)
	mux.HandleFunc("POST /api/hosts/{id}/group", s.handleAssignHostToGroup)

	// Compliance Framework
	mux.HandleFunc("GET /compliance", s.handleCompliance)
	mux.HandleFunc("GET /compliance/{framework}", s.handleComplianceFramework)
	mux.HandleFunc("GET /compliance/{framework}/gaps", s.handleComplianceGaps)
	mux.HandleFunc("POST /api/compliance/mapping", s.handleCreateComplianceMapping)

	// Enhanced Search
	mux.HandleFunc("GET /search", s.handleSearchPage)
	mux.HandleFunc("GET /api/search", s.handleSearchAPI)
	mux.HandleFunc("GET /api/search/suggestions", s.handleSearchSuggestions)
	mux.HandleFunc("POST /api/filters", s.handleSaveFilter)
	mux.HandleFunc("GET /api/filters", s.handleGetFilters)

	// Settings API
	mux.HandleFunc("GET /api/settings/features", s.handleGetFeatureSettings)

	// Historical Trending
	mux.HandleFunc("GET /trending", s.handleTrending)
	mux.HandleFunc("GET /api/trending/velocity", s.handleVelocityAPI)
	mux.HandleFunc("GET /api/trending/mttr", s.handleMTTRAPI)
	mux.HandleFunc("GET /api/trending/predict", s.handlePredictAPI)

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

	// Debug: check total findings by status
	openCount, _ := s.store.GetFindingCountByStatus("Open")
	fixedCount, _ := s.store.GetFindingCountByStatus("Fixed")
	snoozedCount, _ := s.store.GetFindingCountByStatus("Snoozed")
	log.Printf("Dashboard debug: Total findings - Open=%d, Fixed=%d, Snoozed=%d", openCount, fixedCount, snoozedCount)

	crit, _ := s.store.GetVulnCount("Critical")
	high, _ := s.store.GetVulnCount("High")
	totalHosts, _ := s.store.GetHostCount()

	// Fetch scans for trend chart
	scans, err := s.store.GetScans()
	if err != nil {
		log.Printf("Failed to fetch scans for dashboard: %v", err)
	}
	log.Printf("Dashboard: fetched %d scans", len(scans))
	for i, sc := range scans {
		if i < 3 { // Log first 3 for debugging
			log.Printf("  Scan %d: %s, Critical=%d, High=%d, Medium=%d, Low=%d",
				sc.ID, sc.Name, sc.CriticalCount, sc.HighCount, sc.MediumCount, sc.LowCount)
		}
	}

	// Fetch Family Stats (Last 90 days)
	familyStats, err := s.store.GetFamilyStats(90)
	if err != nil {
		log.Printf("Failed to fetch family stats: %v", err)
	}
	log.Printf("Dashboard: fetched %d family stats", len(familyStats))
	for fam, count := range familyStats {
		log.Printf("  Family: %s = %d", fam, count)
	}

	data := struct {
		Stats struct {
			Critical int64
			High     int64
			Hosts    int64
		}
		Scans       []models.Scan
		FamilyStats map[string]int
		Breadcrumbs []Breadcrumb
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
		Breadcrumbs: []Breadcrumb{
			{Text: "Home", URL: "/", Active: true},
		},
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
		Hosts       []models.Host
		Breadcrumbs []Breadcrumb
	}{
		Hosts: hosts,
		Breadcrumbs: []Breadcrumb{
			{Text: "Home", URL: "/"},
			{Text: "Hosts", URL: "/hosts", Active: true},
		},
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

	// Filter out Info severity findings if setting is enabled
	if s.hideInfoEnabled() {
		filtered := make([]models.Finding, 0, len(findings))
		for _, f := range findings {
			if f.Vuln.Severity != "Info" {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	// Get available groups for assignment dropdown
	groups, _ := s.store.GetTagsByCategory("")

	data := struct {
		Host        *models.Host
		Findings    []models.Finding
		Groups      []models.Tag
		Breadcrumbs []Breadcrumb
	}{
		Host:     host,
		Findings: findings,
		Groups:   groups,
		Breadcrumbs: []Breadcrumb{
			{Text: "Home", URL: "/"},
			{Text: "Hosts", URL: "/hosts"},
			{Text: host.IP, URL: "#", Active: true},
		},
	}

	s.render(w, "host_details.html", data)
}

func (s *Server) handleVulns(w http.ResponseWriter, r *http.Request) {
	vulns, err := s.store.GetVulnerabilities()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Filter out Info severity if setting is enabled
	if s.hideInfoEnabled() {
		filtered := make([]models.Vulnerability, 0, len(vulns))
		for _, v := range vulns {
			if v.Severity != "Info" {
				filtered = append(filtered, v)
			}
		}
		vulns = filtered
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
		Breadcrumbs  []Breadcrumb
	}{
		Vulns:        vulns,
		GroupedVulns: groupedVulns,
		Breadcrumbs: []Breadcrumb{
			{Text: "Home", URL: "/"},
			{Text: "Vulnerabilities", URL: "/vulns", Active: true},
		},
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
		Scans       []models.Scan
		Breadcrumbs []Breadcrumb
	}{
		Scans: scans,
		Breadcrumbs: []Breadcrumb{
			{Text: "Home", URL: "/"},
			{Text: "Scans", URL: "/scans", Active: true},
		},
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
	settings, _ := s.store.GetSettings()
	complianceEnabled := settings["compliance_enabled"] == "true"
	hideInfoSeverity := settings["hide_info_severity"] == "true"

	data := struct {
		SLA               map[string]int
		ComplianceEnabled bool
		HideInfoSeverity  bool
		Breadcrumbs       []Breadcrumb
	}{
		SLA:               sla,
		ComplianceEnabled: complianceEnabled,
		HideInfoSeverity:  hideInfoSeverity,
		Breadcrumbs: []Breadcrumb{
			{Text: "Home", URL: "/"},
			{Text: "Admin", URL: "/admin", Active: true},
		},
	}
	s.render(w, "admin.html", data)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// SLA settings
	for _, sev := range []string{"Critical", "High", "Medium", "Low"} {
		key := "sla_" + sev
		val := r.FormValue(key)
		if val != "" {
			if err := s.store.UpdateSetting(key, val); err != nil {
				log.Printf("Failed to update setting %s: %v", key, err)
			}
		}
	}

	// Feature toggles
	complianceEnabled := r.FormValue("compliance_enabled") == "true"
	if err := s.store.UpdateSetting("compliance_enabled", fmt.Sprintf("%v", complianceEnabled)); err != nil {
		log.Printf("Failed to update compliance_enabled: %v", err)
	}

	hideInfoSeverity := r.FormValue("hide_info_severity") == "true"
	if err := s.store.UpdateSetting("hide_info_severity", fmt.Sprintf("%v", hideInfoSeverity)); err != nil {
		log.Printf("Failed to update hide_info_severity: %v", err)
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

func (s *Server) handleClearData(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	var cleared []string
	var errors []string

	// Clear custom groups if requested
	if r.FormValue("clear_groups") == "true" {
		if err := s.store.ClearCustomGroups(); err != nil {
			log.Printf("Failed to clear groups: %v", err)
			errors = append(errors, "groups")
		} else {
			cleared = append(cleared, "groups")
			// Re-seed default groups
			if err := s.store.SeedDefaultGroups(); err != nil {
				log.Printf("Failed to re-seed groups: %v", err)
			}
		}
	}

	// Clear settings if requested
	if r.FormValue("clear_settings") == "true" {
		if err := s.store.ClearSettings(); err != nil {
			log.Printf("Failed to clear settings: %v", err)
			errors = append(errors, "settings")
		} else {
			cleared = append(cleared, "settings")
		}
	}

	// Clear audit log if requested
	if r.FormValue("clear_audit") == "true" {
		if err := s.store.ClearAuditLog(); err != nil {
			log.Printf("Failed to clear audit log: %v", err)
			errors = append(errors, "audit log")
		} else {
			cleared = append(cleared, "audit log")
		}
	}

	// Clear saved filters if requested
	if r.FormValue("clear_filters") == "true" {
		if err := s.store.ClearSavedFilters(); err != nil {
			log.Printf("Failed to clear saved filters: %v", err)
			errors = append(errors, "saved filters")
		} else {
			cleared = append(cleared, "saved filters")
		}
	}

	// Clear search history if requested
	if r.FormValue("clear_search_history") == "true" {
		if err := s.store.ClearSearchHistory(); err != nil {
			log.Printf("Failed to clear search history: %v", err)
			errors = append(errors, "search history")
		} else {
			cleared = append(cleared, "search history")
		}
	}

	// Log the action
	if len(cleared) > 0 {
		s.audit(r, "CLEAR_DATA", "admin", fmt.Sprintf("Cleared: %v", cleared))
	}

	http.Redirect(w, r, "/admin?status=clear_success", http.StatusSeeOther)
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
	// Parse time period (default 30 days)
	daysStr := r.URL.Query().Get("days")
	days := 30
	if daysStr != "" {
		fmt.Sscanf(daysStr, "%d", &days)
	}

	// Gather comprehensive metrics
	hostCount, _ := s.store.GetHostCount()
	severityCounts, _ := s.store.GetOpenFindingsBySeverity()
	topVulns, _ := s.store.GetTopVulnerabilities(10)
	weeklyTrend, _ := s.store.GetFindingsTrendByWeek(12)
	remediationStats, _ := s.store.GetRemediationStats(days)
	groupRisk, _ := s.store.GetRiskByGroup()
	mttr, _ := s.store.GetMTTRStats(days)
	slaBreaches, _ := s.store.GetSLACompliance()
	topRisky, _ := s.store.GetTopRiskyHosts(10)
	aging, _ := s.store.GetAgingStats()

	// Calculate security posture score (0-100)
	totalOpen := severityCounts["Critical"]*10 + severityCounts["High"]*5 + severityCounts["Medium"]*2 + severityCounts["Low"]
	var postureScore float64 = 100
	if hostCount > 0 {
		riskPerHost := float64(totalOpen) / float64(hostCount)
		postureScore = 100 - (riskPerHost * 2) // Deduct 2 points per risk unit per host
		if postureScore < 0 {
			postureScore = 0
		}
	}

	// Calculate SLA compliance percentage
	slaCompliance := 100.0
	if hostCount > 0 {
		uniqueBreachHosts := make(map[uint]bool)
		for _, b := range slaBreaches {
			uniqueBreachHosts[b.HostID] = true
		}
		slaCompliance = 100.0 * (1.0 - float64(len(uniqueBreachHosts))/float64(hostCount))
	}

	// Filter out Info severity if enabled
	hideInfo := s.hideInfoEnabled()
	if hideInfo {
		delete(severityCounts, "Info")
		filtered := make([]storage.VulnSummary, 0)
		for _, v := range topVulns {
			if v.Severity != "Info" {
				filtered = append(filtered, v)
			}
		}
		topVulns = filtered
	}

	data := struct {
		Days             int
		Date             string
		HostCount        int64
		SeverityCounts   map[string]int64
		TopVulns         []storage.VulnSummary
		WeeklyTrend      []storage.WeeklyTrend
		RemediationStats *storage.RemediationStats
		GroupRisk        []storage.GroupRiskSummary
		MTTR             map[string]float64
		SLABreaches      []models.Finding
		TopRiskyHosts    []storage.HostRiskSummary
		Aging            map[string]int
		PostureScore     float64
		SLACompliance    float64
		HideInfo         bool
		Breadcrumbs      []Breadcrumb
	}{
		Days:             days,
		Date:             time.Now().Format("Jan 02, 2006"),
		HostCount:        hostCount,
		SeverityCounts:   severityCounts,
		TopVulns:         topVulns,
		WeeklyTrend:      weeklyTrend,
		RemediationStats: remediationStats,
		GroupRisk:        groupRisk,
		MTTR:             mttr,
		SLABreaches:      slaBreaches,
		TopRiskyHosts:    topRisky,
		Aging:            aging,
		PostureScore:     postureScore,
		SLACompliance:    slaCompliance,
		HideInfo:         hideInfo,
		Breadcrumbs: []Breadcrumb{
			{Text: "Home", URL: "/"},
			{Text: "Reports", URL: "/reports", Active: true},
		},
	}

	s.render(w, "reports.html", data)
}

func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	ghosts, _ := s.store.GetGhostHosts(30) // Default 30 days
	zombies, _ := s.store.GetZombieFindings()
	cohorts, _ := s.store.GetAgingCohorts()

	data := struct {
		Ghosts      []models.Host
		Zombies     []models.Finding
		Cohorts     map[string]int64
		Breadcrumbs []Breadcrumb
	}{
		Ghosts:  ghosts,
		Zombies: zombies,
		Cohorts: cohorts,
		Breadcrumbs: []Breadcrumb{
			{Text: "Home", URL: "/"},
			{Text: "Analytics", URL: "/analytics", Active: true},
		},
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
		Breadcrumbs   []Breadcrumb
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
		Breadcrumbs: []Breadcrumb{
			{Text: "Home", URL: "/"},
			{Text: "Reports", URL: "#"},
			{Text: "Executive Brief", URL: "/reports/executive", Active: true},
		},
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

	// Wrap diff in a struct if not already to add breadcrumbs.
	// GetScanDiff returns a *models.DiffReport. We need to wrap it.
	// Wait, previous code was `s.render(w, "scan_diff.html", diff)`.
	// I need to change that to a struct wrapping diff and breadcrumbs.

	data := struct {
		Report      *models.DiffReport
		Breadcrumbs []Breadcrumb
	}{
		Report: diff,
		Breadcrumbs: []Breadcrumb{
			{Text: "Home", URL: "/"},
			{Text: "Scans", URL: "/scans"},
			{Text: "Diff Report", URL: "#", Active: true},
		},
	}

	s.render(w, "scan_diff.html", data)
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
	// ... (content truncated in view, so I will append handlers at the end of file instead of relying on context here)
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

func (s *Server) handleUpdateHostCriticality(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	var id uint
	fmt.Sscanf(idStr, "%d", &id)

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	criticality := r.FormValue("criticality")

	if err := s.store.UpdateHostCriticality(id, criticality); err != nil {
		http.Error(w, "Failed to update criticality", http.StatusInternalServerError)
		return
	}
	s.audit(r, "UPDATE_CRITICALITY", fmt.Sprintf("Host ID: %d", id), fmt.Sprintf("Set to %s", criticality))

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	logs, err := s.store.GetAuditLogs(100)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	data := struct {
		Logs        []models.AuditLog
		Breadcrumbs []Breadcrumb
	}{
		Logs: logs,
		Breadcrumbs: []Breadcrumb{
			{Text: "Home", URL: "/"},
			{Text: "Audit Log", URL: "/admin/audit", Active: true},
		},
	}
	s.render(w, "audit.html", data)
}

func (s *Server) audit(r *http.Request, action, target, details string) {
	user := "System"
	if u := s.getCurrentUser(r); u != nil {
		user = u.Username
	} else if s.cfg.Auth.Enabled == false {
		user = "Anonymous"
	}
	ip := r.RemoteAddr

	entry := &models.AuditLog{
		User:      user,
		Action:    action,
		Target:    target,
		Details:   details,
		IPAddress: ip,
	}
	if err := s.store.CreateAuditLog(entry); err != nil {
		log.Printf("Failed to create audit log: %v", err)
	}
}

// ==================== Asset Groups Handlers ====================

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.GetAssetGroups()
	if err != nil {
		log.Printf("Error fetching asset groups: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Group by category
	groupsByCategory := make(map[string][]storage.AssetGroup)
	for _, g := range groups {
		cat := string(g.Tag.Category)
		groupsByCategory[cat] = append(groupsByCategory[cat], g)
	}

	data := struct {
		GroupsByCategory map[string][]storage.AssetGroup
		Breadcrumbs      []Breadcrumb
	}{
		GroupsByCategory: groupsByCategory,
		Breadcrumbs: []Breadcrumb{
			{Text: "Home", URL: "/"},
			{Text: "Groups", URL: "/groups", Active: true},
		},
	}

	s.render(w, "groups.html", data)
}

func (s *Server) handleGroupDetails(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	hosts, err := s.store.GetHostsByTag(name)
	if err != nil {
		log.Printf("Error fetching hosts for group %s: %v", name, err)
	}

	stats, err := s.store.GetGroupStats(name)
	if err != nil {
		log.Printf("Error fetching stats for group %s: %v", name, err)
		stats = &storage.GroupStats{}
	}

	findings, err := s.store.GetFindingsByTag(name)
	if err != nil {
		log.Printf("Error fetching findings for group %s: %v", name, err)
	}

	// Filter out Info severity findings if setting is enabled
	if s.hideInfoEnabled() {
		filtered := make([]models.Finding, 0, len(findings))
		for _, f := range findings {
			if f.Vuln.Severity != "Info" {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	// Get the tag info
	tags, _ := s.store.GetTagsByCategory("")
	var groupTag models.Tag
	for _, t := range tags {
		if t.Name == name {
			groupTag = t
			break
		}
	}

	data := struct {
		Group struct {
			Tag models.Tag
		}
		Hosts       []models.Host
		Findings    []models.Finding
		Stats       *storage.GroupStats
		Breadcrumbs []Breadcrumb
	}{
		Group: struct{ Tag models.Tag }{Tag: groupTag},
		Hosts:    hosts,
		Findings: findings,
		Stats:    stats,
		Breadcrumbs: []Breadcrumb{
			{Text: "Home", URL: "/"},
			{Text: "Groups", URL: "/groups"},
			{Text: name, URL: "#", Active: true},
		},
	}

	s.render(w, "group_details.html", data)
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	tag := &models.Tag{
		Name:     r.FormValue("name"),
		Category: models.TagCategory(r.FormValue("category")),
		Color:    r.FormValue("color"),
		Icon:     r.FormValue("icon"),
	}

	if err := s.store.CreateGroup(tag); err != nil {
		log.Printf("Error creating group: %v", err)
		http.Error(w, "Failed to create group", http.StatusInternalServerError)
		return
	}

	s.audit(r, "CREATE_GROUP", tag.Name, fmt.Sprintf("Category: %s", tag.Category))
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
}

func (s *Server) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	var id uint
	fmt.Sscanf(idStr, "%d", &id)

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	color := r.FormValue("color")
	icon := r.FormValue("icon")

	if err := s.store.UpdateGroup(id, name, color, icon); err != nil {
		log.Printf("Error updating group: %v", err)
		http.Error(w, "Failed to update group", http.StatusInternalServerError)
		return
	}

	s.audit(r, "UPDATE_GROUP", fmt.Sprintf("ID: %d", id), fmt.Sprintf("Name: %s", name))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	var id uint
	fmt.Sscanf(idStr, "%d", &id)

	// Get group name for audit
	group, _ := s.store.GetGroupByID(id)
	groupName := "Unknown"
	if group != nil {
		groupName = group.Name
	}

	if err := s.store.DeleteGroup(id); err != nil {
		log.Printf("Error deleting group: %v", err)
		http.Error(w, "Failed to delete group", http.StatusInternalServerError)
		return
	}

	s.audit(r, "DELETE_GROUP", groupName, "")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleAssignHostToGroup(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	var id uint
	fmt.Sscanf(idStr, "%d", &id)

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	groupName := r.FormValue("group")
	// Get the tag to find its color
	tags, _ := s.store.GetTagsByCategory("")
	color := "#0d6efd"
	for _, t := range tags {
		if t.Name == groupName {
			color = t.Color
			break
		}
	}

	if err := s.store.AddHostTag(id, groupName, color); err != nil {
		http.Error(w, "Failed to assign host to group", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ==================== Compliance Handlers ====================

func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request) {
	// Check if compliance is enabled
	settings, _ := s.store.GetSettings()
	if settings["compliance_enabled"] != "true" {
		data := struct {
			Disabled    bool
			Breadcrumbs []Breadcrumb
		}{
			Disabled: true,
			Breadcrumbs: []Breadcrumb{
				{Text: "Home", URL: "/"},
				{Text: "Compliance", URL: "/compliance", Active: true},
			},
		}
		s.render(w, "compliance.html", data)
		return
	}

	frameworks, err := s.store.GetComplianceFrameworks()
	if err != nil {
		log.Printf("Error fetching compliance frameworks: %v", err)
	}

	// Get stats for each framework
	type FrameworkWithStats struct {
		Framework models.ComplianceFramework
		Stats     *storage.FrameworkStats
	}
	var frameworksWithStats []FrameworkWithStats

	for _, fw := range frameworks {
		stats, _ := s.store.GetFrameworkStats(fw.Code)
		frameworksWithStats = append(frameworksWithStats, FrameworkWithStats{
			Framework: fw,
			Stats:     stats,
		})
	}

	data := struct {
		Frameworks  []FrameworkWithStats
		Breadcrumbs []Breadcrumb
	}{
		Frameworks: frameworksWithStats,
		Breadcrumbs: []Breadcrumb{
			{Text: "Home", URL: "/"},
			{Text: "Compliance", URL: "/compliance", Active: true},
		},
	}

	s.render(w, "compliance.html", data)
}

func (s *Server) handleComplianceFramework(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("framework")

	frameworks, _ := s.store.GetComplianceFrameworks()
	var framework models.ComplianceFramework
	for _, fw := range frameworks {
		if fw.Code == code {
			framework = fw
			break
		}
	}

	controls, err := s.store.GetComplianceControls(framework.ID)
	if err != nil {
		log.Printf("Error fetching controls: %v", err)
	}

	stats, _ := s.store.GetFrameworkStats(code)

	data := struct {
		Framework   models.ComplianceFramework
		Controls    []models.ComplianceControl
		Stats       *storage.FrameworkStats
		Breadcrumbs []Breadcrumb
	}{
		Framework: framework,
		Controls:  controls,
		Stats:     stats,
		Breadcrumbs: []Breadcrumb{
			{Text: "Home", URL: "/"},
			{Text: "Compliance", URL: "/compliance"},
			{Text: code, URL: "#", Active: true},
		},
	}

	s.render(w, "compliance_framework.html", data)
}

func (s *Server) handleComplianceGaps(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("framework")

	gaps, err := s.store.GetComplianceGaps(code)
	if err != nil {
		log.Printf("Error fetching compliance gaps: %v", err)
	}

	frameworks, _ := s.store.GetComplianceFrameworks()
	var framework models.ComplianceFramework
	for _, fw := range frameworks {
		if fw.Code == code {
			framework = fw
			break
		}
	}

	data := struct {
		Framework   models.ComplianceFramework
		Gaps        []storage.ComplianceGap
		Breadcrumbs []Breadcrumb
	}{
		Framework: framework,
		Gaps:      gaps,
		Breadcrumbs: []Breadcrumb{
			{Text: "Home", URL: "/"},
			{Text: "Compliance", URL: "/compliance"},
			{Text: code, URL: fmt.Sprintf("/compliance/%s", code)},
			{Text: "Gaps", URL: "#", Active: true},
		},
	}

	s.render(w, "compliance_gaps.html", data)
}

func (s *Server) handleCreateComplianceMapping(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	var vulnID, controlID uint
	fmt.Sscanf(r.FormValue("vulnerability_id"), "%d", &vulnID)
	fmt.Sscanf(r.FormValue("control_id"), "%d", &controlID)
	source := r.FormValue("source")
	if source == "" {
		source = "Manual"
	}

	if err := s.store.CreateComplianceMapping(vulnID, controlID, source); err != nil {
		http.Error(w, "Failed to create mapping", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ==================== Search Handlers ====================

func (s *Server) handleSearchPage(w http.ResponseWriter, r *http.Request) {
	filters, _ := s.store.GetSavedFilters()

	data := struct {
		SavedFilters []models.SavedFilter
		Breadcrumbs  []Breadcrumb
	}{
		SavedFilters: filters,
		Breadcrumbs: []Breadcrumb{
			{Text: "Home", URL: "/"},
			{Text: "Search", URL: "/search", Active: true},
		},
	}

	s.render(w, "search.html", data)
}

func (s *Server) handleSearchAPI(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
	}

	// Parse filter DSL
	criteria := parseFilterDSL(query)

	results, err := s.store.GlobalSearch(criteria, limit)
	if err != nil {
		log.Printf("Search error: %v", err)
		http.Error(w, "Search failed", http.StatusInternalServerError)
		return
	}

	// Filter out Info severity results if setting is enabled
	if s.hideInfoEnabled() {
		filtered := make([]storage.SearchResult, 0, len(results))
		for _, r := range results {
			if r.Severity != "Info" {
				filtered = append(filtered, r)
			}
		}
		results = filtered
	}

	// Record search history
	userID := "anonymous"
	if u := s.getCurrentUser(r); u != nil {
		userID = u.Username
	}
	s.store.AddSearchHistory(query, userID, len(results))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleSearchSuggestions(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("q")
	suggestions, _ := s.store.GetSearchSuggestions(prefix, 10)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(suggestions)
}

func (s *Server) handleSaveFilter(w http.ResponseWriter, r *http.Request) {
	var filter models.SavedFilter
	if err := json.NewDecoder(r.Body).Decode(&filter); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := s.store.CreateSavedFilter(&filter); err != nil {
		http.Error(w, "Failed to save filter", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(filter)
}

func (s *Server) handleGetFilters(w http.ResponseWriter, r *http.Request) {
	filters, err := s.store.GetSavedFilters()
	if err != nil {
		http.Error(w, "Failed to get filters", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(filters)
}

// parseFilterDSL parses a filter DSL string into FilterCriteria
func parseFilterDSL(query string) storage.FilterCriteria {
	criteria := storage.FilterCriteria{
		Query: query,
	}

	parts := strings.Fields(query)
	var freeText []string

	for _, part := range parts {
		if strings.Contains(part, ":") {
			kv := strings.SplitN(part, ":", 2)
			key := strings.ToLower(kv[0])
			value := kv[1]

			switch key {
			case "severity":
				criteria.Severity = append(criteria.Severity, value)
			case "status":
				criteria.Status = append(criteria.Status, value)
			case "tag":
				criteria.Tags = append(criteria.Tags, value)
			case "compliance":
				criteria.Compliance = value
			}
		} else {
			freeText = append(freeText, part)
		}
	}

	if len(freeText) > 0 {
		criteria.Query = strings.Join(freeText, " ")
	} else {
		criteria.Query = ""
	}

	return criteria
}

// ==================== Trending Handlers ====================

func (s *Server) handleTrending(w http.ResponseWriter, r *http.Request) {
	// Get velocity data for last 12 weeks
	velocity, _ := s.store.GetVelocityMetrics(7, 12)

	// Get MTTR trend
	mttr, _ := s.store.GetMTTRTrend(90)

	data := struct {
		Velocity    []storage.VelocityMetric
		MTTRTrend   []storage.MTTRTrend
		Breadcrumbs []Breadcrumb
	}{
		Velocity:  velocity,
		MTTRTrend: mttr,
		Breadcrumbs: []Breadcrumb{
			{Text: "Home", URL: "/"},
			{Text: "Trending", URL: "/trending", Active: true},
		},
	}

	s.render(w, "trending.html", data)
}

func (s *Server) handleVelocityAPI(w http.ResponseWriter, r *http.Request) {
	periodStr := r.URL.Query().Get("period")
	countStr := r.URL.Query().Get("count")

	period := 7
	count := 12
	if periodStr != "" {
		fmt.Sscanf(periodStr, "%d", &period)
	}
	if countStr != "" {
		fmt.Sscanf(countStr, "%d", &count)
	}

	velocity, err := s.store.GetVelocityMetrics(period, count)
	if err != nil {
		http.Error(w, "Failed to get velocity data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(velocity)
}

func (s *Server) handleMTTRAPI(w http.ResponseWriter, r *http.Request) {
	daysStr := r.URL.Query().Get("days")
	days := 90
	if daysStr != "" {
		fmt.Sscanf(daysStr, "%d", &days)
	}

	mttr, err := s.store.GetMTTRTrend(days)
	if err != nil {
		http.Error(w, "Failed to get MTTR data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mttr)
}

func (s *Server) handleGetFeatureSettings(w http.ResponseWriter, r *http.Request) {
	settings, _ := s.store.GetSettings()
	features := map[string]bool{
		"compliance_enabled":  settings["compliance_enabled"] == "true",
		"hide_info_severity": settings["hide_info_severity"] == "true",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(features)
}

// hideInfoEnabled returns true if Info severity should be hidden
func (s *Server) hideInfoEnabled() bool {
	settings, _ := s.store.GetSettings()
	return settings["hide_info_severity"] == "true"
}

func (s *Server) handlePredictAPI(w http.ResponseWriter, r *http.Request) {
	// Simple linear regression prediction for open findings
	snapshots, err := s.store.GetMetricSnapshots("open_findings", 30)
	if err != nil || len(snapshots) < 2 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"prediction": nil,
			"message":    "Insufficient data for prediction",
		})
		return
	}

	// Calculate linear regression
	n := float64(len(snapshots))
	var sumX, sumY, sumXY, sumX2 float64
	for i, s := range snapshots {
		x := float64(i)
		y := s.Value
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}

	slope := (n*sumXY - sumX*sumY) / (n*sumX2 - sumX*sumX)
	intercept := (sumY - slope*sumX) / n

	// Predict next 7 days
	predictions := make([]map[string]interface{}, 7)
	lastX := float64(len(snapshots) - 1)
	for i := 0; i < 7; i++ {
		x := lastX + float64(i+1)
		predictions[i] = map[string]interface{}{
			"day":   i + 1,
			"value": slope*x + intercept,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"slope":       slope,
		"intercept":   intercept,
		"predictions": predictions,
	})
}
