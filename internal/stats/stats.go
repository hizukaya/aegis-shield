package stats

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type QueryLogItem struct {
	ID         uint64    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Domain     string    `json:"domain"`
	QType      string    `json:"type"`
	Blocked    bool      `json:"blocked"`
	DurationMs float64   `json:"duration_ms"`
	ClientIP   string    `json:"client_ip"`
}

type DomainCount struct {
	Domain string `json:"domain"`
	Count  uint64 `json:"count"`
}

type Snapshot struct {
	StartTime       time.Time     `json:"start_time"`
	UptimeSeconds   int64         `json:"uptime_seconds"`
	TotalQueries    uint64        `json:"total_queries"`
	BlockedQueries  uint64        `json:"blocked_queries"`
	AllowedQueries  uint64        `json:"allowed_queries"`
	BlockRate       float64       `json:"block_rate"`
	TopBlocked      []DomainCount `json:"top_blocked"`
	RecentLogs      []QueryLogItem `json:"recent_logs"`
	RulesLoaded     int           `json:"rules_loaded"`
}

type Collector struct {
	mu             sync.RWMutex
	startTime      time.Time
	totalQueries   uint64
	blockedQueries uint64
	allowedQueries uint64
	querySeq       uint64
	topBlocked     map[string]uint64
	recentLogs     []QueryLogItem
	recentMax      int
	statsFilePath  string
	dirty          bool
	stopChan       chan struct{}
}

func NewCollector() *Collector {
	// Keep stats file next to executable if possible, otherwise in LocalAppData
	execPath, err := os.Executable()
	statsDir := ""
	if err == nil {
		statsDir = filepath.Dir(execPath)
	}
	if statsDir == "" || !isDirWritable(statsDir) {
		appData := os.Getenv("LOCALAPPDATA")
		if appData == "" {
			appData = os.TempDir()
		}
		statsDir = filepath.Join(appData, "AegisShield")
		_ = os.MkdirAll(statsDir, 0755)
	}

	c := &Collector{
		startTime:     time.Now(),
		topBlocked:    make(map[string]uint64),
		recentLogs:    make([]QueryLogItem, 0, 100),
		recentMax:     100,
		statsFilePath: filepath.Join(statsDir, "aegis_stats.json"),
		stopChan:      make(chan struct{}),
	}

	c.loadPreviousStats()

	// Flush to disk every 30 seconds to protect USB flash memory from excessive writes
	go c.flushLoop()

	return c
}

func isDirWritable(dir string) bool {
	testFile := filepath.Join(dir, ".aegis_perm_test")
	f, err := os.Create(testFile)
	if err != nil {
		return false
	}
	f.Close()
	_ = os.Remove(testFile)
	return true
}

func (c *Collector) RecordQuery(domain, qtype, clientIP string, blocked bool, duration time.Duration) {
	seq := atomic.AddUint64(&c.querySeq, 1)
	atomic.AddUint64(&c.totalQueries, 1)
	if blocked {
		atomic.AddUint64(&c.blockedQueries, 1)
	} else {
		atomic.AddUint64(&c.allowedQueries, 1)
	}

	item := QueryLogItem{
		ID:         seq,
		Timestamp:  time.Now(),
		Domain:     domain,
		QType:      qtype,
		Blocked:    blocked,
		DurationMs: float64(duration.Microseconds()) / 1000.0,
		ClientIP:   clientIP,
	}

	c.mu.Lock()
	c.dirty = true
	if blocked {
		c.topBlocked[domain]++
	}

	// Ring buffer of last 100 queries
	c.recentLogs = append(c.recentLogs, item)
	if len(c.recentLogs) > c.recentMax {
		c.recentLogs = c.recentLogs[len(c.recentLogs)-c.recentMax:]
	}
	c.mu.Unlock()
}

func (c *Collector) GetSnapshot(rulesLoaded int) Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := atomic.LoadUint64(&c.totalQueries)
	blocked := atomic.LoadUint64(&c.blockedQueries)
	allowed := atomic.LoadUint64(&c.allowedQueries)

	var blockRate float64
	if total > 0 {
		blockRate = (float64(blocked) / float64(total)) * 100.0
	}

	// Sort top 10 blocked
	topList := make([]DomainCount, 0, len(c.topBlocked))
	for d, cnt := range c.topBlocked {
		topList = append(topList, DomainCount{Domain: d, Count: cnt})
	}
	sort.Slice(topList, func(i, j int) bool {
		return topList[i].Count > topList[j].Count
	})
	if len(topList) > 10 {
		topList = topList[:10]
	}

	// Copy logs in reverse chronological order
	logsCopy := make([]QueryLogItem, len(c.recentLogs))
	for i, item := range c.recentLogs {
		logsCopy[len(c.recentLogs)-1-i] = item
	}

	return Snapshot{
		StartTime:      c.startTime,
		UptimeSeconds:  int64(time.Since(c.startTime).Seconds()),
		TotalQueries:   total,
		BlockedQueries: blocked,
		AllowedQueries: allowed,
		BlockRate:      blockRate,
		TopBlocked:     topList,
		RecentLogs:     logsCopy,
		RulesLoaded:    rulesLoaded,
	}
}

func (c *Collector) loadPreviousStats() {
	data, err := os.ReadFile(c.statsFilePath)
	if err != nil {
		return
	}

	var prev struct {
		TotalQueries   uint64            `json:"total_queries"`
		BlockedQueries uint64            `json:"blocked_queries"`
		AllowedQueries uint64            `json:"allowed_queries"`
		TopBlocked     map[string]uint64 `json:"top_blocked_map"`
	}

	if err := json.Unmarshal(data, &prev); err == nil {
		atomic.StoreUint64(&c.totalQueries, prev.TotalQueries)
		atomic.StoreUint64(&c.blockedQueries, prev.BlockedQueries)
		atomic.StoreUint64(&c.allowedQueries, prev.AllowedQueries)
		if prev.TopBlocked != nil {
			c.topBlocked = prev.TopBlocked
		}
		log.Printf("[Stats] Restored prior session stats: %d total, %d blocked", prev.TotalQueries, prev.BlockedQueries)
	}
}

func (c *Collector) flushLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.Flush()
		case <-c.stopChan:
			c.Flush()
			return
		}
	}
}

func (c *Collector) Flush() {
	c.mu.Lock()
	if !c.dirty {
		c.mu.Unlock()
		return
	}
	c.dirty = false

	payload := struct {
		TotalQueries   uint64            `json:"total_queries"`
		BlockedQueries uint64            `json:"blocked_queries"`
		AllowedQueries uint64            `json:"allowed_queries"`
		TopBlocked     map[string]uint64 `json:"top_blocked_map"`
		LastUpdated    time.Time         `json:"last_updated"`
	}{
		TotalQueries:   atomic.LoadUint64(&c.totalQueries),
		BlockedQueries: atomic.LoadUint64(&c.blockedQueries),
		AllowedQueries: atomic.LoadUint64(&c.allowedQueries),
		TopBlocked:     c.topBlocked,
		LastUpdated:    time.Now(),
	}
	c.mu.Unlock()

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return
	}

	tmpFile := c.statsFilePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err == nil {
		_ = os.Rename(tmpFile, c.statsFilePath)
	}
}

func (c *Collector) Stop() {
	close(c.stopChan)
}
