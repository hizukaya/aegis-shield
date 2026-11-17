package coredns

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"aegis-shield/internal/lists"
	"aegis-shield/internal/stats"

	"github.com/miekg/dns"
)

const (
	PrimaryUpstream   = "1.1.1.1:53"
	SecondaryUpstream = "8.8.8.8:53"
	ForwardTimeout    = 3 * time.Second
)

type Server struct {
	listsMgr   *lists.Manager
	statsCol   *stats.Collector
	udpServer  *dns.Server
	tcpServer  *dns.Server
	forwarder  *dns.Client
	paused     int32 // 1 if paused, 0 if active
	pauseUntil int64 // unix timestamp in seconds
	mu         sync.RWMutex
}

func NewServer(listsMgr *lists.Manager, statsCol *stats.Collector) *Server {
	s := &Server{
		listsMgr: listsMgr,
		statsCol: statsCol,
		forwarder: &dns.Client{
			Timeout: ForwardTimeout,
		},
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleDNSQuery)

	s.udpServer = &dns.Server{
		Addr:    "127.0.0.1:53",
		Net:     "udp",
		Handler: mux,
	}

	s.tcpServer = &dns.Server{
		Addr:    "127.0.0.1:53",
		Net:     "tcp",
		Handler: mux,
	}

	return s
}

func (s *Server) Start() error {
	errChan := make(chan error, 2)

	go func() {
		log.Printf("[CoreDNS] Listening on UDP 127.0.0.1:53...")
		if err := s.udpServer.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("UDP server error: %w", err)
		}
	}()

	go func() {
		log.Printf("[CoreDNS] Listening on TCP 127.0.0.1:53...")
		if err := s.tcpServer.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("TCP server error: %w", err)
		}
	}()

	// Brief pause to catch immediate bind failures (e.g. port already in use or permission denied)
	select {
	case err := <-errChan:
		return err
	case <-time.After(150 * time.Millisecond):
		return nil
	}
}

func (s *Server) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_ = s.udpServer.ShutdownContext(ctx)
	_ = s.tcpServer.ShutdownContext(ctx)
	log.Printf("[CoreDNS] Server stopped cleanly")
}

func (s *Server) Pause(duration time.Duration) {
	atomic.StoreInt32(&s.paused, 1)
	atomic.StoreInt64(&s.pauseUntil, time.Now().Add(duration).Unix())
	log.Printf("[CoreDNS] Protection paused for %v", duration)
}

func (s *Server) Resume() {
	atomic.StoreInt32(&s.paused, 0)
	atomic.StoreInt64(&s.pauseUntil, 0)
	log.Printf("[CoreDNS] Protection resumed")
}

func (s *Server) IsPaused() (bool, time.Duration) {
	if atomic.LoadInt32(&s.paused) == 0 {
		return false, 0
	}
	until := atomic.LoadInt64(&s.pauseUntil)
	remaining := time.Until(time.Unix(until, 0))
	if remaining <= 0 {
		// Auto unpause
		atomic.StoreInt32(&s.paused, 0)
		return false, 0
	}
	return true, remaining
}

func (s *Server) handleDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()

	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	q := r.Question[0]
	qTypeStr := dns.TypeToString[q.Qtype]
	rawDomain := q.Name
	cleanDomain := strings.ToLower(strings.TrimSuffix(rawDomain, "."))

	clientIP := "127.0.0.1"
	if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		clientIP = addr.IP.String()
	} else if addr, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP.String()
	}

	isPaused, _ := s.IsPaused()
	blocked := false

	if !isPaused {
		blocked = s.listsMgr.IsBlocked(cleanDomain)
	}

	if blocked {
		// Respond with sinkhole address: A -> 0.0.0.0, AAAA -> ::, TTL 60
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Authoritative = true
		resp.RecursionAvailable = true

		switch q.Qtype {
		case dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.IPv4zero,
			})
		case dns.TypeAAAA:
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				AAAA: net.IPv6zero,
			})
		default:
			// For non-IP queries on blocked domains, return empty NOERROR
		}

		_ = w.WriteMsg(resp)
		s.statsCol.RecordQuery(cleanDomain, qTypeStr, clientIP, true, time.Since(start))
		return
	}

	// Not blocked: Forward to upstream 1.1.1.1 (fallback 8.8.8.8)
	network := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		network = "tcp"
	}

	resp, rtt, err := s.forwardQuery(r, network)
	if err != nil {
		log.Printf("[CoreDNS] Forward error for %s: %v", cleanDomain, err)
		dns.HandleFailed(w, r)
		s.statsCol.RecordQuery(cleanDomain, qTypeStr, clientIP, false, time.Since(start))
		return
	}

	_ = w.WriteMsg(resp)
	_ = rtt
	s.statsCol.RecordQuery(cleanDomain, qTypeStr, clientIP, false, time.Since(start))
}

func (s *Server) forwardQuery(req *dns.Msg, network string) (*dns.Msg, time.Duration, error) {
	client := &dns.Client{
		Net:     network,
		Timeout: ForwardTimeout,
	}

	// Try Primary (1.1.1.1)
	resp, rtt, err := client.Exchange(req, PrimaryUpstream)
	if err == nil && resp != nil {
		return resp, rtt, nil
	}

	// Fallback to Secondary (8.8.8.8)
	resp, rtt, err = client.Exchange(req, SecondaryUpstream)
	if err == nil && resp != nil {
		return resp, rtt, nil
	}

	return nil, 0, fmt.Errorf("both primary and fallback upstreams failed")
}
