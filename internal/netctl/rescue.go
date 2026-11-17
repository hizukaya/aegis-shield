package netctl

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

type InterfaceDNSBackup struct {
	Name          string   `json:"name"`
	Index         int      `json:"index"`
	IsDHCP        bool     `json:"is_dhcp"`
	StaticServers []string `json:"static_servers"`
	IPv6IsDHCP    bool     `json:"ipv6_is_dhcp"`
	IPv6Servers   []string `json:"ipv6_servers"`
}

type RescueState struct {
	Timestamp      time.Time            `json:"timestamp"`
	OriginalStates []InterfaceDNSBackup `json:"original_states"`
	ActivePID      int                  `json:"active_pid"`
}

func getRescueFilePaths() (jsonPath string, batPath string) {
	tempDir := os.TempDir()
	jsonPath = filepath.Join(tempDir, "aegis_rescue.json")
	batPath = filepath.Join(tempDir, "aegis_rescue.bat")
	return
}

// SaveRescueState saves interface restoration data to both JSON and emergency BAT script.
func SaveRescueState(backups []InterfaceDNSBackup) error {
	jsonPath, batPath := getRescueFilePaths()

	state := RescueState{
		Timestamp:      time.Now(),
		OriginalStates: backups,
		ActivePID:      os.Getpid(),
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(jsonPath, data, 0644); err != nil {
		log.Printf("[NetCtl] Warning: Could not write rescue JSON: %v", err)
	}

	// Generate emergency .bat file in %TEMP%
	batContent := "@echo off\r\n"
	batContent += "echo ==============================================\r\n"
	batContent += "echo   AEGIS Shield Emergency DNS Rescue Utility\r\n"
	batContent += "echo ==============================================\r\n"
	batContent += "echo Restoring network adapters to original DNS...\r\n"

	for _, b := range backups {
		if b.IsDHCP {
			batContent += fmt.Sprintf("netsh interface ipv4 set dnsservers name=\"%s\" source=dhcp\r\n", b.Name)
		} else if len(b.StaticServers) > 0 {
			batContent += fmt.Sprintf("netsh interface ipv4 set dnsservers name=\"%s\" static %s validate=no\r\n", b.Name, b.StaticServers[0])
			for i := 1; i < len(b.StaticServers); i++ {
				batContent += fmt.Sprintf("netsh interface ipv4 add dnsservers name=\"%s\" %s index=%d validate=no\r\n", b.Name, b.StaticServers[i], i+1)
			}
		}

		if b.IPv6IsDHCP {
			batContent += fmt.Sprintf("netsh interface ipv6 set dnsservers name=\"%s\" source=dhcp\r\n", b.Name)
		}
	}

	batContent += "ipconfig /flushdns\r\n"
	batContent += "echo Done! Internet DNS restored.\r\n"
	batContent += "del \"%TEMP%\\aegis_rescue.json\" 2>nul\r\n"
	batContent += "del \"%~f0\" 2>nul\r\n"

	if err := os.WriteFile(batPath, []byte(batContent), 0755); err != nil {
		log.Printf("[NetCtl] Warning: Could not write rescue BAT: %v", err)
	}

	log.Printf("[NetCtl] Rescue files created at %s and %s", jsonPath, batPath)
	return nil
}

// ClearRescueFiles cleans up rescue artifacts after successful restoration.
func ClearRescueFiles() {
	jsonPath, batPath := getRescueFilePaths()
	_ = os.Remove(jsonPath)
	_ = os.Remove(batPath)
}

// HasPendingRescue checks if an uncleaned rescue file exists from an unexpected termination.
func HasPendingRescue() bool {
	jsonPath, _ := getRescueFilePaths()
	info, err := os.Stat(jsonPath)
	return err == nil && info.Size() > 0
}

// LoadRescueState loads the saved rescue state from disk.
func LoadRescueState() (*RescueState, error) {
	jsonPath, _ := getRescueFilePaths()
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, err
	}

	var state RescueState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}
