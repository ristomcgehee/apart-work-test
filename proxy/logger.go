package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// RequestLog represents a logged HTTP request and response
type RequestLog struct {
	ID              string            `json:"id"`
	Timestamp       time.Time         `json:"timestamp"`
	Method          string            `json:"method"`
	Domain          string            `json:"domain"`
	Path            string            `json:"path"`
	Headers         map[string]string `json:"headers"`
	Body            string            `json:"body,omitempty"`
	ResponseStatus  int               `json:"response_status,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	ResponseBody    string            `json:"response_body,omitempty"`
	PcapFile        string            `json:"pcap_file"`
}

// Logger handles request logging
type Logger struct {
	logsDir    string
	logFile    *os.File
	mu         sync.Mutex
	requests   []RequestLog
	requestIdx map[string]int // maps request ID to index in requests slice
}

// NewLogger creates a new logger
func NewLogger(logsDir string) (*Logger, error) {
	logPath := filepath.Join(logsDir, "requests.jsonl")

	// Open or create log file
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	logger := &Logger{
		logsDir:    logsDir,
		logFile:    file,
		requests:   make([]RequestLog, 0),
		requestIdx: make(map[string]int),
	}

	// Load existing logs
	if err := logger.loadExistingLogs(); err != nil {
		fmt.Printf("Warning: failed to load existing logs: %v\n", err)
	}

	return logger, nil
}

func (l *Logger) loadExistingLogs() error {
	logPath := filepath.Join(l.logsDir, "requests.jsonl")
	data, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	// Parse each line
	lines := splitLines(data)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var req RequestLog
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		l.requests = append(l.requests, req)
	}

	return nil
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

// LogRequest logs an HTTP request
func (l *Logger) LogRequest(req *http.Request) *RequestLog {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Create log entry
	headers := make(map[string]string)
	for key, values := range req.Header {
		if len(values) > 0 {
			// Redact sensitive headers
			if key == "Authorization" || key == "X-Api-Key" || key == "Api-Key" {
				headers[key] = "[REDACTED]"
			} else {
				headers[key] = values[0]
			}
		}
	}

	// Read request body for POST/PUT/PATCH requests
	var body string
	if req.Body != nil && (req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH") {
		bodyBytes, err := io.ReadAll(req.Body)
		if err == nil {
			// Restore the body so it can be forwarded
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			// Limit body size to 10KB for logging
			if len(bodyBytes) > 10*1024 {
				body = string(bodyBytes[:10*1024]) + "... [truncated]"
			} else {
				body = string(bodyBytes)
			}
		}
	}

	// Get current PCAP file name
	pcapFile := fmt.Sprintf("capture_%s.pcap", time.Now().Format("20060102_150405"))

	entry := RequestLog{
		ID:        uuid.New().String()[:8],
		Timestamp: time.Now().UTC(),
		Method:    req.Method,
		Domain:    req.Host,
		Path:      req.URL.Path,
		Headers:   headers,
		Body:      body,
		PcapFile:  pcapFile,
	}

	// Write to file
	data, err := json.Marshal(entry)
	if err != nil {
		fmt.Printf("Failed to marshal log entry: %v\n", err)
		return &entry
	}

	if _, err := l.logFile.Write(append(data, '\n')); err != nil {
		fmt.Printf("Failed to write log entry: %v\n", err)
	}
	l.logFile.Sync()

	// Add to in-memory list
	l.requests = append(l.requests, entry)
	l.requestIdx[entry.ID] = len(l.requests) - 1

	// Keep only last 1000 requests in memory
	if len(l.requests) > 1000 {
		// Rebuild index for remaining requests
		l.requests = l.requests[len(l.requests)-1000:]
		l.requestIdx = make(map[string]int)
		for i, r := range l.requests {
			l.requestIdx[r.ID] = i
		}
	}

	return &entry
}

// LogResponse updates a request log with response data
func (l *Logger) LogResponse(requestID string, resp *http.Response) {
	if resp == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	idx, ok := l.requestIdx[requestID]
	if !ok {
		return
	}

	// Extract response headers
	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	// Read response body
	var body string
	if resp.Body != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			// Restore the body so it can be forwarded
			resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			// Limit body size to 10KB for logging
			if len(bodyBytes) > 10*1024 {
				body = string(bodyBytes[:10*1024]) + "... [truncated]"
			} else {
				body = string(bodyBytes)
			}
		}
	}

	// Update the request entry
	l.requests[idx].ResponseStatus = resp.StatusCode
	l.requests[idx].ResponseHeaders = headers
	l.requests[idx].ResponseBody = body

	// Write updated entry to file (append as new line - we'll have duplicates but that's ok)
	data, err := json.Marshal(l.requests[idx])
	if err != nil {
		fmt.Printf("Failed to marshal response log entry: %v\n", err)
		return
	}

	if _, err := l.logFile.Write(append(data, '\n')); err != nil {
		fmt.Printf("Failed to write response log entry: %v\n", err)
	}
	l.logFile.Sync()
}

// GetRequests returns all logged requests
func (l *Logger) GetRequests() []RequestLog {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Return a copy
	result := make([]RequestLog, len(l.requests))
	copy(result, l.requests)
	return result
}

// Close closes the logger
func (l *Logger) Close() error {
	return l.logFile.Close()
}
