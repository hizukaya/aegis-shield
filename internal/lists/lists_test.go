package lists

import (
	"strings"
	"testing"
)

func TestEmbeddedListLoaded(t *testing.T) {
	mgr := NewManager()
	count := mgr.RulesCount()
	if count < 50000 {
		t.Fatalf("Expected at least 50,000 embedded rules, got %d", count)
	}
	t.Logf("Successfully loaded %d embedded rules", count)
}

func TestIsBlocked(t *testing.T) {
	mgr := NewManager()

	// Test known blocked domains from StevenBlack hosts
	knownAds := []string{
		"doubleclick.net",
		"adservice.google.com",
		"pagead2.googlesyndication.com",
		"prebid.adnxs.com",
		"gum.criteo.com",
	}

	for _, domain := range knownAds {
		if !mgr.IsBlocked(domain) {
			t.Errorf("Expected domain %s to be blocked", domain)
		}
	}

	// Test subdomain matching (e.g. any sub of doubleclick.net should be blocked)
	if !mgr.IsBlocked("tracker.doubleclick.net") {
		t.Errorf("Expected sub.doubleclick.net to be blocked by parent rule")
	}

	// Test Whitelist: Acceptance Test #3: youtube.com must work!
	whitelistDomains := []string{
		"youtube.com",
		"www.youtube.com",
		"googlevideo.com",
		"r1---sn-uxa75ne6.googlevideo.com",
		"ytimg.com",
		"www.google.com",
		"cloudflare.com",
	}

	for _, domain := range whitelistDomains {
		if mgr.IsBlocked(domain) {
			t.Errorf("Expected whitelisted domain %s to NOT be blocked", domain)
		}
	}
}

func TestCustomRules(t *testing.T) {
	mgr := NewManager()

	testDomain := "my-custom-ad-tracker.xyz"
	if mgr.IsBlocked(testDomain) {
		t.Fatalf("Domain %s should not be blocked initially", testDomain)
	}

	mgr.AddBlacklist(testDomain)
	if !mgr.IsBlocked(testDomain) {
		t.Fatalf("Domain %s should be blocked after AddBlacklist", testDomain)
	}

	// Now whitelist it
	mgr.AddWhitelist(testDomain)
	if mgr.IsBlocked(testDomain) {
		t.Fatalf("Domain %s should not be blocked after AddWhitelist", testDomain)
	}
}

func TestParseCustomHosts(t *testing.T) {
	sampleHosts := `
# Sample comment
0.0.0.0 bad-ad.com
127.0.0.1 malicious-tracker.net
0.0.0.0 0.0.0.0
::1 localhost
`
	mgr := &Manager{
		blockedMap:   make(map[string]struct{}),
		whitelistMap: make(map[string]struct{}),
		customBlock:  make(map[string]struct{}),
	}

	count := mgr.parseAndReplace(strings.NewReader(sampleHosts))
	if count != 2 {
		t.Fatalf("Expected 2 valid rules, got %d", count)
	}

	if !mgr.IsBlocked("bad-ad.com") {
		t.Errorf("Expected bad-ad.com to be blocked")
	}
	if !mgr.IsBlocked("malicious-tracker.net") {
		t.Errorf("Expected malicious-tracker.net to be blocked")
	}
}
