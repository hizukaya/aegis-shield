package stats

import (
	"testing"
	"time"
)

func TestStatsCollector(t *testing.T) {
	c := NewCollector()
	defer c.Stop()

	// Initial check
	snap := c.GetSnapshot(76000)
	if snap.TotalQueries != 0 || snap.BlockedQueries != 0 {
		t.Fatalf("Expected 0 initial queries, got total=%d, blocked=%d", snap.TotalQueries, snap.BlockedQueries)
	}

	// Record queries
	c.RecordQuery("doubleclick.net", "A", "127.0.0.1", true, 500*time.Microsecond)
	c.RecordQuery("doubleclick.net", "A", "127.0.0.1", true, 400*time.Microsecond)
	c.RecordQuery("youtube.com", "A", "127.0.0.1", false, 15*time.Millisecond)
	c.RecordQuery("google.com", "AAAA", "127.0.0.1", false, 12*time.Millisecond)

	snap = c.GetSnapshot(76000)
	if snap.TotalQueries != 4 {
		t.Errorf("Expected 4 total queries, got %d", snap.TotalQueries)
	}
	if snap.BlockedQueries != 2 {
		t.Errorf("Expected 2 blocked queries, got %d", snap.BlockedQueries)
	}
	if snap.AllowedQueries != 2 {
		t.Errorf("Expected 2 allowed queries, got %d", snap.AllowedQueries)
	}
	if snap.BlockRate != 50.0 {
		t.Errorf("Expected 50.0%% block rate, got %.1f%%", snap.BlockRate)
	}
	if len(snap.TopBlocked) == 0 || snap.TopBlocked[0].Domain != "doubleclick.net" {
		t.Errorf("Expected doubleclick.net in TopBlocked")
	}
	if len(snap.RecentLogs) != 4 {
		t.Errorf("Expected 4 recent logs, got %d", len(snap.RecentLogs))
	}
}
