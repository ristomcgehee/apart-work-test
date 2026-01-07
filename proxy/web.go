package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

//go:embed static/*
var staticFiles embed.FS

// WebServer serves the web UI
type WebServer struct {
	logger  *Logger
	logsDir string
}

// NewWebServer creates a new web server
func NewWebServer(logger *Logger, logsDir string) *WebServer {
	return &WebServer{
		logger:  logger,
		logsDir: logsDir,
	}
}

// Start starts the web server
func (w *WebServer) Start(addr string) error {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/requests", w.handleRequests)
	mux.HandleFunc("/api/pcap/", w.handlePcapDownload)
	mux.HandleFunc("/api/pcap-list", w.handlePcapList)

	// Static files
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("failed to get static files: %w", err)
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	fmt.Printf("Web UI available at http://localhost%s\n", addr)
	return http.ListenAndServe(addr, mux)
}

func (w *WebServer) handleRequests(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Access-Control-Allow-Origin", "*")

	requests := w.logger.GetRequests()

	// Return in reverse order (newest first)
	reversed := make([]RequestLog, len(requests))
	for i, req := range requests {
		reversed[len(requests)-1-i] = req
	}

	if err := json.NewEncoder(rw).Encode(reversed); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}

func (w *WebServer) handlePcapDownload(rw http.ResponseWriter, r *http.Request) {
	// Extract filename from path
	filename := strings.TrimPrefix(r.URL.Path, "/api/pcap/")
	if filename == "" {
		http.Error(rw, "No filename specified", http.StatusBadRequest)
		return
	}

	// Sanitize filename to prevent directory traversal
	filename = filepath.Base(filename)
	if !strings.HasSuffix(filename, ".pcap") {
		http.Error(rw, "Invalid file type", http.StatusBadRequest)
		return
	}

	pcapPath := filepath.Join(w.logsDir, filename)

	// Check if file exists
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		http.Error(rw, "PCAP file not found", http.StatusNotFound)
		return
	}

	rw.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	rw.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	http.ServeFile(rw, r, pcapPath)
}

func (w *WebServer) handlePcapList(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Access-Control-Allow-Origin", "*")

	// List all PCAP files
	files, err := os.ReadDir(w.logsDir)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	var pcapFiles []string
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".pcap") {
			pcapFiles = append(pcapFiles, file.Name())
		}
	}

	if err := json.NewEncoder(rw).Encode(pcapFiles); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}
