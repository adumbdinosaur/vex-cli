package security

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
)

// -- Interfaces for Testing --

type FileSystem interface {
	ReadFile(name string) ([]byte, error)
}

type RealFileSystem struct{}

func (r *RealFileSystem) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }

var fsOps FileSystem = &RealFileSystem{}

// -- Key Management --

const (
	PublicKeyFile = "/etc/vex-cli/vex_management_key.pub"
)

var (
	managementKey ed25519.PublicKey
	keyOnce       sync.Once
	keyErr        error
)

// Init loads the management public key for signature verification
func Init() error {
	keyOnce.Do(func() {
		log.Println("Security: Loading management key...")

		data, err := fsOps.ReadFile(PublicKeyFile)
		if err != nil {
			keyErr = fmt.Errorf("failed to load management key from %s: %w", PublicKeyFile, err)
			log.Printf("Security: WARNING - %v", keyErr)
			log.Println("Security: Commands requiring authorization will be REJECTED")
			return
		}

		// Key file contains hex-encoded Ed25519 public key
		keyBytes, err := hex.DecodeString(string(data))
		if err != nil {
			// Try raw bytes
			keyBytes = data
		}

		if len(keyBytes) != ed25519.PublicKeySize {
			keyErr = fmt.Errorf("invalid key size: expected %d bytes, got %d", ed25519.PublicKeySize, len(keyBytes))
			log.Printf("Security: WARNING - %v", keyErr)
			return
		}

		managementKey = ed25519.PublicKey(keyBytes)
		log.Println("Security: Management key loaded successfully")
	})

	return keyErr
}

// -- Signature Verification --

// SignedCommand represents a command that requires cryptographic authorization
type SignedCommand struct {
	Command   string `json:"command"`
	Args      string `json:"args"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"` // hex-encoded Ed25519 signature
}

// VerifyCommand checks that a signed command was authorized by the management key.
// Commands that lower restrictions (unlocking blocks/throttles) must be verified.
func VerifyCommand(cmd *SignedCommand) error {
	if managementKey == nil {
		return fmt.Errorf("management key not loaded; all restricted commands are DENIED")
	}

	// Reconstruct the signed message (command + args + timestamp)
	message := fmt.Sprintf("%s:%s:%d", cmd.Command, cmd.Args, cmd.Timestamp)
	messageBytes := []byte(message)

	sigBytes, err := hex.DecodeString(cmd.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	if !ed25519.Verify(managementKey, messageBytes, sigBytes) {
		return fmt.Errorf("SIGNATURE VERIFICATION FAILED for command '%s'", cmd.Command)
	}

	log.Printf("Security: Command '%s' signature verified", cmd.Command)
	return nil
}

// IsRestrictionLoweringCommand returns true if the command requires authorization
func IsRestrictionLoweringCommand(command string) bool {
	restrictedCommands := map[string]bool{
		"unlock":          true,
		"unblock":         true,
		"lift-throttle":   true,
		"restore-network": true,
		"clear-penance":   true,
		"set-standard":    true,
	}
	return restrictedCommands[command]
}

// -- Binary Self-Verification --

// VerifyBinaryIntegrity performs a SHA-256 self-check of the running binary.
// Used by the Anti-Tamper subsystem to detect modifications.
func VerifyBinaryIntegrity(expectedHash string) error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable path: %w", err)
	}

	data, err := os.ReadFile(execPath)
	if err != nil {
		return fmt.Errorf("failed to read executable: %w", err)
	}

	hash := sha256.Sum256(data)
	actualHash := hex.EncodeToString(hash[:])

	if actualHash != expectedHash {
		return fmt.Errorf("BINARY INTEGRITY CHECK FAILED: expected %s, got %s", expectedHash, actualHash)
	}

	log.Println("Security: Binary integrity verified")
	return nil
}

// -- Serialization Helpers --

// ParseSignedCommand deserializes a JSON signed command
func ParseSignedCommand(data []byte) (*SignedCommand, error) {
	var cmd SignedCommand
	if err := json.Unmarshal(data, &cmd); err != nil {
		return nil, fmt.Errorf("failed to parse signed command: %w", err)
	}
	return &cmd, nil
}
