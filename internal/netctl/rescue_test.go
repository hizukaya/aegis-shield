package netctl

import (
	"os"
	"testing"
)

func TestRescuePersistence(t *testing.T) {
	// Clean up any existing rescue files
	ClearRescueFiles()

	if HasPendingRescue() {
		t.Fatalf("Expected no pending rescue initially")
	}

	mockBackups := []InterfaceDNSBackup{
		{
			Name:          "Wi-Fi",
			Index:         6,
			IsDHCP:        true,
			StaticServers: []string{},
			IPv6IsDHCP:    true,
		},
		{
			Name:          "Ethernet",
			Index:         12,
			IsDHCP:        false,
			StaticServers: []string{"1.1.1.1", "8.8.8.8"},
			IPv6IsDHCP:    false,
		},
	}

	// Save rescue state
	if err := SaveRescueState(mockBackups); err != nil {
		t.Fatalf("SaveRescueState failed: %v", err)
	}

	if !HasPendingRescue() {
		t.Fatalf("Expected HasPendingRescue to be true after saving")
	}

	// Verify loaded state
	loaded, err := LoadRescueState()
	if err != nil {
		t.Fatalf("LoadRescueState failed: %v", err)
	}

	if len(loaded.OriginalStates) != 2 {
		t.Fatalf("Expected 2 interfaces, got %d", len(loaded.OriginalStates))
	}

	if loaded.OriginalStates[0].Name != "Wi-Fi" || !loaded.OriginalStates[0].IsDHCP {
		t.Errorf("Wi-Fi backup mismatch")
	}

	if loaded.OriginalStates[1].Name != "Ethernet" || loaded.OriginalStates[1].IsDHCP {
		t.Errorf("Ethernet backup mismatch")
	}

	// Verify emergency BAT file was also created
	_, batPath := getRescueFilePaths()
	batData, err := os.ReadFile(batPath)
	if err != nil {
		t.Fatalf("Emergency rescue BAT file not created: %v", err)
	}

	batStr := string(batData)
	if len(batStr) == 0 {
		t.Errorf("Emergency BAT file is empty")
	}

	// Clean up
	ClearRescueFiles()

	if HasPendingRescue() {
		t.Errorf("Expected HasPendingRescue to be false after ClearRescueFiles")
	}
}
