package license

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"
)

// Master public key for AEGIS Shield licensing verification
// (In production, the private key is held securely by the owner/issuer)
var MasterPublicKeyHex = "6f8904e578c772e0d37e61882d242ee9da1b181b5ffbe5be4a3ff27f311c1d68"

type LicensePayload struct {
	Licensee  string `json:"licensee"`
	Tier      string `json:"tier"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
	Features  string `json:"features"`
}

type LicenseFile struct {
	Payload   LicensePayload `json:"payload"`
	Signature string         `json:"signature"`
}

type Info struct {
	IsValid   bool      `json:"is_valid"`
	Licensee  string    `json:"licensee"`
	Tier      string    `json:"tier"`
	ExpiresAt time.Time `json:"expires_at"`
	Message   string    `json:"message"`
}

// VerifyLicense checks for aegis.lic in the executable directory and verifies its Ed25519 signature.
func VerifyLicense() Info {
	execPath, err := os.Executable()
	licDir := "."
	if err == nil {
		licDir = filepath.Dir(execPath)
	}

	licPath := filepath.Join(licDir, "aegis.lic")
	data, err := os.ReadFile(licPath)
	if err != nil {
		return Info{
			IsValid:  true,
			Licensee: "Pongsakorn (Owner)",
			Tier:     "Community / Portable Edition",
			Message:  "Active — Portable Free Edition",
		}
	}

	var lic LicenseFile
	if err := json.Unmarshal(data, &lic); err != nil {
		return Info{
			IsValid: false,
			Tier:    "Unlicensed",
			Message: "Corrupt license file format",
		}
	}

	pubKeyBytes, err := hex.DecodeString(MasterPublicKeyHex)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return Info{
			IsValid: false,
			Tier:    "Unlicensed",
			Message: "Invalid public key configuration",
		}
	}

	sigBytes, err := hex.DecodeString(lic.Signature)
	if err != nil {
		return Info{
			IsValid: false,
			Tier:    "Unlicensed",
			Message: "Invalid signature format",
		}
	}

	payloadBytes, err := json.Marshal(lic.Payload)
	if err != nil {
		return Info{
			IsValid: false,
			Tier:    "Unlicensed",
			Message: "Payload serialization error",
		}
	}

	if !ed25519.Verify(pubKeyBytes, payloadBytes, sigBytes) {
		log.Printf("[License] Signature verification failed")
		return Info{
			IsValid: false,
			Tier:    "Unlicensed",
			Message: "Signature verification failed",
		}
	}

	var expTime time.Time
	if lic.Payload.ExpiresAt != "NEVER" && lic.Payload.ExpiresAt != "" {
		t, err := time.Parse("2006-01-02", lic.Payload.ExpiresAt)
		if err == nil {
			expTime = t
			if time.Now().After(expTime) {
				return Info{
					IsValid:  false,
					Licensee: lic.Payload.Licensee,
					Tier:     "Expired",
					Message:  "License expired on " + lic.Payload.ExpiresAt,
				}
			}
		}
	}

	return Info{
		IsValid:   true,
		Licensee:  lic.Payload.Licensee,
		Tier:      lic.Payload.Tier,
		ExpiresAt: expTime,
		Message:   "Licensed to " + lic.Payload.Licensee + " (" + lic.Payload.Tier + ")",
	}
}
