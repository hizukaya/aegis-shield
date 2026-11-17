package netctl

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Controller struct {
	mu           sync.Mutex
	backups      []InterfaceDNSBackup
	isActivated  bool
	restoredOnce bool
}

type InterfaceStatus struct {
	Name           string   `json:"name"`
	OriginalType   string   `json:"original_type"`
	OriginalDNS    []string `json:"original_dns"`
	CurrentDNS     string   `json:"current_dns"`
	Status         string   `json:"status"`
}

func NewController() *Controller {
	return &Controller{
		backups: make([]InterfaceDNSBackup, 0),
	}
}

// CheckAndRecoverPreviousSession restores DNS if a crash occurred previously.
func CheckAndRecoverPreviousSession() bool {
	if !HasPendingRescue() {
		return false
	}

	log.Printf("[NetCtl] Found previous uncleaned rescue file! Restoring original DNS now...")
	state, err := LoadRescueState()
	if err != nil {
		log.Printf("[NetCtl] Error reading rescue file: %v", err)
		return false
	}

	for _, b := range state.OriginalStates {
		restoreInterface(b)
	}

	FlushDNS()
	ClearRescueFiles()
	log.Printf("[NetCtl] Successfully recovered %d network interface(s) from crash rescue state.", len(state.OriginalStates))
	return true
}

func (c *Controller) Activate() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isActivated {
		return nil
	}

	// 1. Discover connected active interfaces
	activeIfaces, err := getConnectedInterfaces()
	if err != nil {
		return fmt.Errorf("failed to discover active interfaces: %w", err)
	}

	if len(activeIfaces) == 0 {
		return fmt.Errorf("no connected network interfaces found")
	}

	c.backups = make([]InterfaceDNSBackup, 0, len(activeIfaces))

	// 2. Read current DNS configuration for each active interface
	for _, ifaceName := range activeIfaces {
		backup := inspectInterfaceDNS(ifaceName)
		c.backups = append(c.backups, backup)
		log.Printf("[NetCtl] Backed up DNS for '%s' (DHCP=%v, Static=%v)", ifaceName, backup.IsDHCP, backup.StaticServers)
	}

	// 3. Persist rescue state before making any modifications
	if err := SaveRescueState(c.backups); err != nil {
		log.Printf("[NetCtl] Warning: Failed to save rescue state: %v", err)
	}

	// 4. Switch active interfaces to 127.0.0.1
	for _, b := range c.backups {
		setInterfaceDNS(b.Name, "127.0.0.1")
	}

	// 5. Flush DNS resolver cache
	FlushDNS()

	c.isActivated = true
	c.restoredOnce = false
	log.Printf("[NetCtl] Successfully switched %d interface(s) to AEGIS Shield (127.0.0.1)", len(c.backups))
	return nil
}

func (c *Controller) Restore() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isActivated || c.restoredOnce {
		return
	}
	c.restoredOnce = true

	log.Printf("[NetCtl] Restoring %d interface(s) to original DNS...", len(c.backups))
	for _, b := range c.backups {
		restoreInterface(b)
	}

	FlushDNS()
	ClearRescueFiles()
	c.isActivated = false
	log.Printf("[NetCtl] DNS restored successfully to original configuration.")
}

func (c *Controller) GetStatus() []InterfaceStatus {
	c.mu.Lock()
	defer c.mu.Unlock()

	res := make([]InterfaceStatus, 0, len(c.backups))
	for _, b := range c.backups {
		origType := "Static"
		if b.IsDHCP {
			origType = "DHCP"
		}
		status := "Active (127.0.0.1)"
		if !c.isActivated {
			status = "Restored"
		}
		res = append(res, InterfaceStatus{
			Name:         b.Name,
			OriginalType: origType,
			OriginalDNS:  b.StaticServers,
			CurrentDNS:   "127.0.0.1",
			Status:       status,
		})
	}
	return res
}

func getConnectedInterfaces() ([]string, error) {
	cmd := exec.Command("netsh", "interface", "ipv4", "show", "interfaces")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var connected []string
	scanner := bufio.NewScanner(bytes.NewReader(out))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Idx") || strings.HasPrefix(line, "---") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 5 {
			state := strings.ToLower(fields[3])
			// Remaining fields form the interface name
			name := strings.Join(fields[4:], " ")

			if state == "connected" {
				// Filter out loopback and virtual default switch bridges if they don't have gateway
				if !strings.Contains(strings.ToLower(name), "loopback") {
					// Verify interface has default gateway or valid IP
					if hasActiveConnectivity(name) {
						connected = append(connected, name)
					}
				}
			}
		}
	}

	return connected, nil
}

func hasActiveConnectivity(name string) bool {
	cmd := exec.Command("netsh", "interface", "ipv4", "show", "config", fmt.Sprintf("name=\"%s\"", name))
	out, err := cmd.Output()
	if err != nil {
		return true // If unsure, include it
	}
	text := string(out)
	// Check for Default Gateway or IP Address
	return strings.Contains(text, "IP Address") || strings.Contains(text, "Default Gateway")
}

func inspectInterfaceDNS(name string) InterfaceDNSBackup {
	backup := InterfaceDNSBackup{
		Name:          name,
		IsDHCP:        true,
		StaticServers: make([]string, 0),
		IPv6IsDHCP:    true,
		IPv6Servers:   make([]string, 0),
	}

	cmd := exec.Command("netsh", "interface", "ipv4", "show", "config", fmt.Sprintf("name=\"%s\"", name))
	out, err := cmd.Output()
	if err != nil {
		return backup
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	isStaticDNS := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lower := strings.ToLower(line)

		if strings.Contains(lower, "statically configured dns servers:") {
			isStaticDNS = true
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				ip := strings.TrimSpace(parts[1])
				if ip != "" && ip != "None" {
					backup.StaticServers = append(backup.StaticServers, ip)
				}
			}
		} else if strings.Contains(lower, "dns servers configured through dhcp:") {
			backup.IsDHCP = true
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				ip := strings.TrimSpace(parts[1])
				if ip != "" && ip != "None" {
					backup.StaticServers = append(backup.StaticServers, ip)
				}
			}
		} else if isStaticDNS {
			// Check if subsequent lines contain secondary static DNS IPs
			fields := strings.Fields(line)
			if len(fields) == 1 && strings.Count(fields[0], ".") == 3 {
				backup.StaticServers = append(backup.StaticServers, fields[0])
			} else if strings.Contains(line, ":") {
				isStaticDNS = false
			}
		}
	}

	if len(backup.StaticServers) > 0 && !backup.IsDHCP {
		backup.IsDHCP = false
	}

	return backup
}

func setInterfaceDNS(name, dnsIP string) {
	// netsh interface ipv4 set dnsservers name="<name>" static 127.0.0.1 validate=no
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "dnsservers", fmt.Sprintf("name=\"%s\"", name), "static", dnsIP, "validate=no")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[NetCtl] Error setting IPv4 DNS for '%s': %v (out: %s)", name, err, strings.TrimSpace(string(out)))
	} else {
		log.Printf("[NetCtl] Successfully set IPv4 DNS for '%s' to %s", name, dnsIP)
	}

	// Disable IPv6 DNS or point to ::1 to prevent bypass
	cmd6 := exec.Command("netsh", "interface", "ipv6", "set", "dnsservers", fmt.Sprintf("name=\"%s\"", name), "static", "::1", "validate=no")
	_ = cmd6.Run()
}

func restoreInterface(b InterfaceDNSBackup) {
	if b.IsDHCP || len(b.StaticServers) == 0 {
		cmd := exec.Command("netsh", "interface", "ipv4", "set", "dnsservers", fmt.Sprintf("name=\"%s\"", b.Name), "source=dhcp")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[NetCtl] Error restoring DHCP DNS for '%s': %v (out: %s)", b.Name, err, strings.TrimSpace(string(out)))
		} else {
			log.Printf("[NetCtl] Restored DHCP DNS for '%s'", b.Name)
		}

		cmd6 := exec.Command("netsh", "interface", "ipv6", "set", "dnsservers", fmt.Sprintf("name=\"%s\"", b.Name), "source=dhcp")
		_ = cmd6.Run()
	} else {
		// Restore static primary DNS
		primary := b.StaticServers[0]
		cmd := exec.Command("netsh", "interface", "ipv4", "set", "dnsservers", fmt.Sprintf("name=\"%s\"", b.Name), "static", primary, "validate=no")
		_ = cmd.Run()

		// Restore secondary static DNS
		for i := 1; i < len(b.StaticServers); i++ {
			addCmd := exec.Command("netsh", "interface", "ipv4", "add", "dnsservers", fmt.Sprintf("name=\"%s\"", b.Name), b.StaticServers[i], fmt.Sprintf("index=%d", i+1), "validate=no")
			_ = addCmd.Run()
		}
		log.Printf("[NetCtl] Restored Static DNS %v for '%s'", b.StaticServers, b.Name)
	}
}

// FlushDNS executes ipconfig /flushdns to clear the Windows resolver cache immediately.
func FlushDNS() {
	cmd := exec.Command("ipconfig", "/flushdns")
	_ = cmd.Run()
	time.Sleep(50 * time.Millisecond)
	log.Printf("[NetCtl] Windows DNS resolver cache flushed.")
}
