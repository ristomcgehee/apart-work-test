package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/elazarl/goproxy"
)

func main() {
	proxyAddr := flag.String("proxy", ":8080", "Proxy listen address")
	webAddr := flag.String("web", ":8888", "Web UI listen address")
	logsDir := flag.String("logs", "/logs", "Directory for logs and PCAP files")
	flag.Parse()

	// Ensure logs directory exists
	if err := os.MkdirAll(*logsDir, 0o755); err != nil {
		log.Fatalf("Failed to create logs directory: %v", err)
	}

	// Load or create CA
	ca, err := LoadOrCreateCA(*logsDir)
	if err != nil {
		log.Fatalf("Failed to load/create CA: %v", err)
	}
	fmt.Println("CA certificate ready")

	// Create logger
	logger, err := NewLogger(*logsDir)
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Create proxy
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false

	// Set up MITM for HTTPS
	tlsCert, err := tls.X509KeyPair(ca.CertPEM, ca.KeyPEM)
	if err != nil {
		log.Fatalf("Failed to create TLS cert: %v", err)
	}

	goproxy.GoproxyCa = tlsCert
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&tlsCert)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&tlsCert)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&tlsCert)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&tlsCert)}

	// Handle CONNECT requests (HTTPS)
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	// Log all requests
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		entry := logger.LogRequest(req)
		ctx.UserData = entry.ID // Store request ID for response handler
		fmt.Printf("[%s] %s %s%s\n", entry.ID, req.Method, req.Host, req.URL.Path)
		return req, nil
	})

	// Log all responses
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if requestID, ok := ctx.UserData.(string); ok {
			logger.LogResponse(requestID, resp)
		}
		return resp
	})

	// Start web server in goroutine
	webServer := NewWebServer(logger, *logsDir)
	go func() {
		if err := webServer.Start(*webAddr); err != nil {
			log.Fatalf("Web server failed: %v", err)
		}
	}()

	// Start proxy
	fmt.Printf("Proxy listening on %s\n", *proxyAddr)
	log.Fatal(http.ListenAndServe(*proxyAddr, proxy))
}
