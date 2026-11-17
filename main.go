package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

var (
	blocked = map[string]bool{}
	total   atomic.Uint64
	hits    atomic.Uint64
)

func loadList(path string) {
	f, err := os.Open(path)
	if err != nil {
		log.Println("no blocklist, running pass-through:", err)
		return
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fs := strings.Fields(line)
		d := ""
		if len(fs) >= 2 && (fs[0] == "0.0.0.0" || fs[0] == "127.0.0.1") {
			d = fs[1] // hosts format
		} else {
			d = fs[0] // plain domain
		}
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if d != "" && d != "localhost" {
			blocked[d] = true
		}
	}
	log.Println("loaded", len(blocked), "domains")
}

func isBlocked(name string) bool {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	for {
		if blocked[n] {
			return true
		}
		i := strings.Index(n, ".")
		if i < 0 {
			return false
		}
		n = n[i+1:] // จับ subdomain ด้วย
	}
}

func handle(w dns.ResponseWriter, r *dns.Msg) {
	total.Add(1)
	m := new(dns.Msg)
	m.SetReply(r)
	if len(r.Question) > 0 && isBlocked(r.Question[0].Name) {
		hits.Add(1)
		q := r.Question[0]
		switch q.Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   []byte{0, 0, 0, 0},
			})
		case dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: make([]byte, 16),
			})
		}
		w.WriteMsg(m)
		return
	}
	c := new(dns.Client)
	c.Timeout = 3 * time.Second
	in, _, err := c.Exchange(r, "1.1.1.1:53")
	if err != nil {
		in, _, err = c.Exchange(r, "8.8.8.8:53")
		if err != nil {
			dns.HandleFailed(w, r)
			return
		}
	}
	w.WriteMsg(in)
}

func main() {
	loadList("data/hosts.txt")
	go func() {
		http.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"queries":%d,"blocked":%d,"domains":%d}`,
				total.Load(), hits.Load(), len(blocked))
		})
		http.ListenAndServe("127.0.0.1:8899", nil)
	}()
	for _, proto := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: "127.0.0.1:53", Net: proto, Handler: dns.HandlerFunc(handle)}
		go func(s *dns.Server) { log.Fatal(s.ListenAndServe()) }(srv)
	}
	log.Println("AEGIS core running on 127.0.0.1:53 — Ctrl+C to stop")
	select {}
}
