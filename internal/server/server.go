package server

import (
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/hootmeow/Vuln-Strix/internal/ingest"
	"github.com/hootmeow/Vuln-Strix/internal/models"
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
	s.tmpl, err = template.ParseGlob("internal/server/templates/base.html")
	if err != nil {
		// Fallback
		s.tmpl, err = template.ParseGlob("../../internal/server/templates/base.html")
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

	data := struct {
		Stats struct {
			Critical int64
			High     int64
			Hosts    int64
		}
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
