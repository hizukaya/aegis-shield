package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"aegis-shield/internal/coredns"
	"aegis-shield/internal/license"
	"aegis-shield/internal/lists"
	"aegis-shield/internal/netctl"
	"aegis-shield/internal/stats"
)

//go:embed static/*
var staticFS embed.FS

const BindAddress = "127.0.0.1:8899"

type Server struct {
	httpServer *http.Server
	dnsServer  *coredns.Server
	listsMgr   *lists.Manager
	statsCol   *stats.Collector
	netCtl     *netctl.Controller
	onQuitReq  func()
}

func NewServer(
	dnsServer *coredns.Server,
	listsMgr *lists.Manager,
	statsCol *stats.Collector,
	netCtl *netctl.Controller,
	onQuitReq func(),
) *Server {
	return &Server{
		dnsServer: dnsServer,
		listsMgr:  listsMgr,
		statsCol:  statsCol,
		netCtl:    netCtl,
		onQuitReq: onQuitReq,
	}
}

func (s *Server) Start() error {
	// Strictly bind to 127.0.0.1 loopback only — forbidden on external LAN interfaces
	listener, err := net.Listen("tcp", BindAddress)
	if err != nil {
		return fmt.Errorf("failed to bind loopback dashboard on %s: %w", BindAddress, err)
	}

	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/pause", s.handlePause)
	mux.HandleFunc("/api/resume", s.handleResume)
	mux.HandleFunc("/api/flush-dns", s.handleFlushDNS)
	mux.HandleFunc("/api/restore-and-quit", s.handleRestoreAndQuit)
	mux.HandleFunc("/api/whitelist", s.handleWhitelist)
	mux.HandleFunc("/api/blacklist", s.handleBlacklist)

	// Embedded static file server
	subFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		return fmt.Errorf("embedded static fs error: %w", err)
	}
	fileServer := http.FileServer(http.FS(subFS))
	mux.Handle("/", fileServer)

	s.httpServer = &http.Server{
		Handler:      s.securityMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Printf("[Dashboard] Accessible locally at http://%s", BindAddress)
	go func() {
		if err := s.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("[Dashboard] HTTP server error: %v", err)
		}
	}()

	return nil
}

func (s *Server) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if s.httpServer != nil {
		_ = s.httpServer.Shutdown(ctx)
		log.Printf("[Dashboard] Server stopped cleanly")
	}
}

// securityMiddleware strictly enforces that ONLY requests originating from 127.0.0.1 are accepted.
func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || (host != "127.0.0.1" && host != "::1") {
			http.Error(w, "Forbidden: AEGIS Shield dashboard is accessible via local loopback only.", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	rulesCount := s.listsMgr.RulesCount()
	snap := s.statsCol.GetSnapshot(rulesCount)
	isPaused, pauseRemaining := s.dnsServer.IsPaused()
	licInfo := license.VerifyLicense()
	ifaces := s.netCtl.GetStatus()

	resp := map[string]interface{}{
		"active":              !isPaused,
		"paused":              isPaused,
		"pause_remaining_sec": int64(pauseRemaining.Seconds()),
		"version":             "1.0",
		"uptime_seconds":      snap.UptimeSeconds,
		"total_queries":       snap.TotalQueries,
		"blocked_queries":     snap.BlockedQueries,
		"allowed_queries":     snap.AllowedQueries,
		"block_rate":          snap.BlockRate,
		"rules_count":         snap.RulesLoaded,
		"top_blocked":         snap.TopBlocked,
		"interfaces":          ifaces,
		"license":             licInfo,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	snap := s.statsCol.GetSnapshot(0)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snap.RecentLogs)
}

func (s *Server) handlePause(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Minutes int `json:"minutes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)
	if payload.Minutes <= 0 {
		payload.Minutes = 5
	}

	s.dnsServer.Pause(time.Duration(payload.Minutes) * time.Minute)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "paused",
		"message": fmt.Sprintf("Protection paused for %d minutes", payload.Minutes),
	})
}

func (s *Server) handleResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	s.dnsServer.Resume()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "active",
		"message": "Protection resumed",
	})
}

func (s *Server) handleFlushDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	netctl.FlushDNS()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "DNS resolver cache successfully flushed.",
	})
}

func (s *Server) handleRestoreAndQuit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "quitting",
		"message": "Restoring DNS settings and shutting down...",
	})

	if s.onQuitReq != nil {
		go func() {
			time.Sleep(300 * time.Millisecond)
			s.onQuitReq()
		}()
	}
}

func (s *Server) handleWhitelist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Domain) == "" {
		http.Error(w, "Invalid domain", http.StatusBadRequest)
		return
	}

	s.listsMgr.AddWhitelist(req.Domain)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": fmt.Sprintf("Domain '%s' added to whitelist", req.Domain),
	})
}

func (s *Server) handleBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Domain) == "" {
		http.Error(w, "Invalid domain", http.StatusBadRequest)
		return
	}

	s.listsMgr.AddBlacklist(req.Domain)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": fmt.Sprintf("Domain '%s' added to blocklist", req.Domain),
	})
}
