package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyLicenseDefault(t *testing.T) {
	// Without any aegis.lic present, should fall back to valid Community Edition
	info := VerifyLicense()
	if !info.IsValid {
		t.Errorf("Expected valid community edition license")
	}
	if info.Licensee != "Pongsakorn (Owner)" {
		t.Errorf("Expected licensee Pongsakorn (Owner), got %s", info.Licensee)
	}
}

func TestVerifySignedLicense(t *testing.T) {
	// Generate a test Ed25519 keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Temporarily override MasterPublicKeyHex for testing
	origKey := MasterPublicKeyHex
	MasterPublicKeyHex = hex.EncodeToString(pubKey)
	defer func() { MasterPublicKeyHex = origKey }()

	payload := LicensePayload{
		Licensee:  "Pongsakorn",
		Tier:      "Enterprise Portable USB",
		IssuedAt:  "2026-11-17",
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Format("2006-01-02"),
		Features:  "unlimited,hardware-bound",
	}

	payloadBytes, _ := json.Marshal(payload)
	signature := ed25519.Sign(privKey, payloadBytes)

	licFile := LicenseFile{
		Payload:   payload,
		Signature: hex.EncodeToString(signature),
	}
	licData, _ := json.MarshalIndent(licFile, "", "  ")

	// Write temporary aegis.lic next to binary/in cwd
	execPath, err := os.Executable()
	dir := "."
	if err == nil {
		dir = filepath.Dir(execPath)
	}
	tmpLicPath := filepath.Join(dir, "aegis.lic")
	_ = os.WriteFile(tmpLicPath, licData, 0644)
	defer os.Remove(tmpLicPath)

	info := VerifyLicense()
	if !info.IsValid {
		t.Fatalf("Expected signed license to be valid, got message: %s", info.Message)
	}
	if info.Licensee != "Pongsakorn" {
		t.Errorf("Expected Licensee 'Pongsakorn', got '%s'", info.Licensee)
	}
	if info.Tier != "Enterprise Portable USB" {
		t.Errorf("Expected Tier 'Enterprise Portable USB', got '%s'", info.Tier)
	}
}
