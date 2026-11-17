package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aegis-shield/internal/coredns"
	"aegis-shield/internal/lists"
	"aegis-shield/internal/netctl"
	"aegis-shield/internal/stats"
)

func TestDashboardEndpoints(t *testing.T) {
	listsMgr := lists.NewManager()
	statsCol := stats.NewCollector()
	defer statsCol.Stop()

	dnsServer := coredns.NewServer(listsMgr, statsCol)
	netCtl := netctl.NewController()

	server := NewServer(dnsServer, listsMgr, statsCol, netCtl, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", server.handleStatus)
	mux.HandleFunc("/api/logs", server.handleLogs)
	mux.HandleFunc("/api/pause", server.handlePause)
	mux.HandleFunc("/api/resume", server.handleResume)
	mux.HandleFunc("/api/whitelist", server.handleWhitelist)

	handler := server.securityMiddleware(mux)

	// 1. Test /api/status
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.RemoteAddr = "127.0.0.1:51234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from /api/status, got %d", w.Code)
	}

	var statusResp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("Failed to parse status JSON: %v", err)
	}

	if statusResp["active"] != true {
		t.Errorf("Expected active=true")
	}
	if statusResp["version"] != "1.0" {
		t.Errorf("Expected version 1.0, got %v", statusResp["version"])
	}

	// 2. Test Security Middleware: Reject non-loopback IP (e.g. 192.168.1.100)
	extReq := httptest.NewRequest("GET", "/api/status", nil)
	extReq.RemoteAddr = "192.168.1.100:51234"
	extW := httptest.NewRecorder()
	handler.ServeHTTP(extW, extReq)

	if extW.Code != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for external LAN IP, got %d", extW.Code)
	}

	// 3. Test /api/pause
	pauseBody := strings.NewReader(`{"minutes": 10}`)
	pauseReq := httptest.NewRequest("POST", "/api/pause", pauseBody)
	pauseReq.RemoteAddr = "127.0.0.1:51234"
	pauseW := httptest.NewRecorder()
	handler.ServeHTTP(pauseW, pauseReq)

	if pauseW.Code != http.StatusOK {
		t.Errorf("Expected 200 OK from /api/pause, got %d", pauseW.Code)
	}

	isPaused, _ := dnsServer.IsPaused()
	if !isPaused {
		t.Errorf("Expected DNS server to be paused")
	}

	// 4. Test /api/resume
	resumeReq := httptest.NewRequest("POST", "/api/resume", nil)
	resumeReq.RemoteAddr = "127.0.0.1:51234"
	resumeW := httptest.NewRecorder()
	handler.ServeHTTP(resumeW, resumeReq)

	isPaused, _ = dnsServer.IsPaused()
	if isPaused {
		t.Errorf("Expected DNS server to be resumed")
	}
}
