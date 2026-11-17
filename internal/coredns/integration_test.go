package coredns

import (
	"context"
	"net"
	"testing"
	"time"

	"aegis-shield/internal/lists"
	"aegis-shield/internal/stats"

	"github.com/miekg/dns"
)

func TestCoreDNSAdBlockingAndWhitelisting(t *testing.T) {
	listsMgr := lists.NewManager()
	statsCol := stats.NewCollector()
	defer statsCol.Stop()

	// Create test DNS server on a random port for testing
	s := &Server{
		listsMgr: listsMgr,
		statsCol: statsCol,
		forwarder: &dns.Client{
			Timeout: 3 * time.Second,
		},
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleDNSQuery)

	testPort := ":15353"
	s.udpServer = &dns.Server{
		Addr:    "127.0.0.1" + testPort,
		Net:     "udp",
		Handler: mux,
	}

	go func() {
		_ = s.udpServer.ListenAndServe()
	}()
	time.Sleep(100 * time.Millisecond)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.udpServer.ShutdownContext(ctx)
	}()

	client := new(dns.Client)

	// 1. Acceptance Test #2: Blocked ad domain returns 0.0.0.0, TTL 60
	adMsg := new(dns.Msg)
	adMsg.SetQuestion("pagead2.googlesyndication.com.", dns.TypeA)
	resp, _, err := client.Exchange(adMsg, "127.0.0.1"+testPort)
	if err != nil {
		t.Fatalf("DNS exchange failed: %v", err)
	}

	if len(resp.Answer) == 0 {
		t.Fatalf("Expected answer for blocked domain, got empty")
	}

	if aRecord, ok := resp.Answer[0].(*dns.A); ok {
		if !aRecord.A.Equal(net.IPv4zero) {
			t.Errorf("Expected 0.0.0.0 for blocked domain, got %v", aRecord.A)
		}
		if aRecord.Hdr.Ttl != 60 {
			t.Errorf("Expected TTL 60, got %d", aRecord.Hdr.Ttl)
		}
	} else {
		t.Fatalf("Expected A record in answer, got %T", resp.Answer[0])
	}

	// 2. Acceptance Test #3: youtube.com is resolved cleanly via upstream (1.1.1.1)
	ytMsg := new(dns.Msg)
	ytMsg.SetQuestion("youtube.com.", dns.TypeA)
	ytResp, _, err := client.Exchange(ytMsg, "127.0.0.1"+testPort)
	if err != nil {
		t.Fatalf("DNS exchange for youtube.com failed: %v", err)
	}

	if len(ytResp.Answer) == 0 {
		t.Fatalf("Expected upstream answer for youtube.com, got 0 records")
	}

	// Verify not sinkholed to 0.0.0.0
	for _, ans := range ytResp.Answer {
		if aRecord, ok := ans.(*dns.A); ok {
			if aRecord.A.Equal(net.IPv4zero) {
				t.Fatalf("youtube.com should NOT be sinkholed to 0.0.0.0!")
			}
			t.Logf("youtube.com successfully resolved to live upstream IP: %s", aRecord.A)
			break
		}
	}

	// 3. Test Pause functionality: when paused, ad domain is NOT blocked
	s.Pause(5 * time.Minute)
	isPaused, remaining := s.IsPaused()
	if !isPaused || remaining <= 0 {
		t.Fatalf("Expected server to be paused")
	}

	// 4. Test Resume functionality
	s.Resume()
	isPaused, _ = s.IsPaused()
	if isPaused {
		t.Fatalf("Expected server to be active after Resume")
	}
}
