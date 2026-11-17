package lists

import (
	"bufio"
	_ "embed"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed rules/hosts.txt
var embeddedHostsData []byte

const (
	StevenBlackURL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
	UpdateInterval = 24 * time.Hour
)

type Manager struct {
	mu           sync.RWMutex
	blockedMap   map[string]struct{}
	whitelistMap map[string]struct{}
	customBlock  map[string]struct{}
	etag         string
	lastModified string
	cachePath    string
	rulesCount   int64
	client       *http.Client
}

// Built-in whitelist ensuring mission-critical streaming, Windows Updates, and essential services are never broken.
var defaultWhitelist = []string{
	"youtube.com",
	"www.youtube.com",
	"googlevideo.com",
	"ytimg.com",
	"play.google.com",
	"www.google.com",
	"windowsupdate.com",
	"update.microsoft.com",
	"windowsupdate.microsoft.com",
	"login.microsoftonline.com",
	"live.com",
	"office.com",
	"github.com",
	"githubusercontent.com",
	"cloudflare.com",
	"one.one.one.one",
	"dns.google",
}

func NewManager() *Manager {
	cacheDir := os.Getenv("LOCALAPPDATA")
	if cacheDir == "" {
		cacheDir = os.TempDir()
	}
	aegisDir := filepath.Join(cacheDir, "AegisShield")
	_ = os.MkdirAll(aegisDir, 0755)

	m := &Manager{
		blockedMap:   make(map[string]struct{}),
		whitelistMap: make(map[string]struct{}),
		customBlock:  make(map[string]struct{}),
		cachePath:    filepath.Join(aegisDir, "hosts.cached"),
		client:       &http.Client{Timeout: 30 * time.Second},
	}

	for _, domain := range defaultWhitelist {
		m.whitelistMap[strings.ToLower(domain)] = struct{}{}
	}

	// Try loading cached updated hosts first; if missing, load embedded hosts
	if !m.loadFromCache() {
		m.loadFromData(embeddedHostsData)
	}

	// Start 24h background updater
	go m.updateLoop()

	return m
}

func (m *Manager) RulesCount() int {
	return int(atomic.LoadInt64(&m.rulesCount))
}

func (m *Manager) loadFromCache() bool {
	info, err := os.Stat(m.cachePath)
	if err != nil || info.Size() == 0 {
		return false
	}
	f, err := os.Open(m.cachePath)
	if err != nil {
		return false
	}
	defer f.Close()

	count := m.parseAndReplace(f)
	if count > 0 {
		log.Printf("[Lists] Loaded %d rules from local cache: %s", count, m.cachePath)
		return true
	}
	return false
}

func (m *Manager) loadFromData(data []byte) {
	reader := strings.NewReader(string(data))
	count := m.parseAndReplace(reader)
	log.Printf("[Lists] Loaded %d rules from embedded fallback blocklist", count)
}

func (m *Manager) parseAndReplace(r io.Reader) int {
	newMap := make(map[string]struct{}, 80000)
	scanner := bufio.NewScanner(r)

	// Buffer up to 1MB lines if needed
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, len(buf))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split on whitespace: expecting "0.0.0.0 domain" or "127.0.0.1 domain"
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			ip := fields[0]
			if ip == "0.0.0.0" || ip == "127.0.0.1" {
				domain := strings.ToLower(strings.TrimSpace(fields[1]))
				if isValidDomain(domain) {
					newMap[domain] = struct{}{}
				}
			}
		}
	}

	count := len(newMap)
	m.mu.Lock()
	m.blockedMap = newMap
	atomic.StoreInt64(&m.rulesCount, int64(count))
	m.mu.Unlock()

	return count
}

func isValidDomain(d string) bool {
	if d == "" || d == "localhost" || d == "localhost.localdomain" || d == "local" ||
		d == "broadcasthost" || d == "0.0.0.0" || strings.HasPrefix(d, "ip6-") {
		return false
	}
	return strings.Contains(d, ".")
}

// IsBlocked checks if a domain (or any parent domain) is blocked, taking whitelist into account.
func (m *Manager) IsBlocked(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Whitelist check first
	if _, ok := m.whitelistMap[domain]; ok {
		return false
	}

	// Custom blocked check
	if _, ok := m.customBlock[domain]; ok {
		return true
	}

	// StevenBlack blocked map check (exact match)
	if _, ok := m.blockedMap[domain]; ok {
		return true
	}

	// Subdomain / Parent domain check (e.g. "ad.doubleclick.net" -> "doubleclick.net")
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if _, ok := m.whitelistMap[parent]; ok {
			return false
		}
		if _, ok := m.blockedMap[parent]; ok {
			return true
		}
		if _, ok := m.customBlock[parent]; ok {
			return true
		}
	}

	return false
}

// AddWhitelist adds a custom domain to whitelist.
func (m *Manager) AddWhitelist(domain string) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return
	}
	m.mu.Lock()
	m.whitelistMap[domain] = struct{}{}
	delete(m.customBlock, domain)
	m.mu.Unlock()
}

// AddBlacklist adds a custom domain to blocklist.
func (m *Manager) AddBlacklist(domain string) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return
	}
	m.mu.Lock()
	m.customBlock[domain] = struct{}{}
	delete(m.whitelistMap, domain)
	m.mu.Unlock()
}

func (m *Manager) updateLoop() {
	// First check after 10 minutes to avoid delaying initial startup
	time.Sleep(10 * time.Minute)
	m.checkForUpdates()

	ticker := time.NewTicker(UpdateInterval)
	defer ticker.Stop()

	for range ticker.C {
		m.checkForUpdates()
	}
}

func (m *Manager) checkForUpdates() {
	req, err := http.NewRequest("GET", StevenBlackURL, nil)
	if err != nil {
		return
	}

	m.mu.RLock()
	if m.etag != "" {
		req.Header.Set("If-None-Match", m.etag)
	}
	if m.lastModified != "" {
		req.Header.Set("If-Modified-Since", m.lastModified)
	}
	m.mu.RUnlock()

	resp, err := m.client.Do(req)
	if err != nil {
		log.Printf("[Lists] Background update check failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		log.Printf("[Lists] Blocklist is up to date (304 Not Modified)")
		return
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("[Lists] Background update returned status %d", resp.StatusCode)
		return
	}

	// Save to temp file first to ensure atomic write
	tmpFile := m.cachePath + ".tmp"
	outFile, err := os.Create(tmpFile)
	if err != nil {
		return
	}

	// Stream and parse simultaneously
	teeReader := io.TeeReader(resp.Body, outFile)
	count := m.parseAndReplace(teeReader)
	outFile.Close()

	if count > 1000 {
		_ = os.Rename(tmpFile, m.cachePath)
		m.mu.Lock()
		m.etag = resp.Header.Get("ETag")
		m.lastModified = resp.Header.Get("Last-Modified")
		m.mu.Unlock()
		log.Printf("[Lists] Successfully updated blocklist to %d rules!", count)
	} else {
		_ = os.Remove(tmpFile)
	}
}
