package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	mrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"time"
)

// calculateSRIHashes reads static assets (CSS, JS), computes their SRI hashes,
// and populates the global variables. This is called at startup.
func calculateSRIHashes() error {
	jsFileMap = make(map[string][]byte)
	// shorter.css
	cssBytes, err := os.ReadFile(filepath.Join(config.BaseDir, "css", "shorter.css"))
	if err != nil {
		return fmt.Errorf("failed to read shorter.css: %w", err)
	}
	cssHash := sha256.Sum256(cssBytes)
	cssSRIHash = "sha256-" + base64.StdEncoding.EncodeToString(cssHash[:])

	// Read each JS file once, store its content, and calculate the hash from the stored content.
	jsFilesToLoad := []string{"admin.js", "showText.js"}
	for _, fileName := range jsFilesToLoad {
		slogger.Debug("Attempting to load JS file", "file", fileName)
		filePath := filepath.Join(config.BaseDir, "js", fileName)
		fileBytes, err := os.ReadFile(filePath)
		if err != nil {
			// Use ERROR level to make this highly visible during debugging.
			slogger.Error("Could not read JS file, handler will not be created.", "file", fileName, "path", filePath, "error", err)
			continue
		}

		// Store the file content in the global map.
		jsFileMap[fileName] = fileBytes

		// Calculate the hash from the in-memory bytes.
		hash := sha256.Sum256(fileBytes)
		sriHash := "sha256-" + base64.StdEncoding.EncodeToString(hash[:])

		// Assign the hash to the correct global variable.
		switch fileName {
		case "admin.js":
			adminJsSRIHash = sriHash
		case "showText.js":
			showTextJsSRIHash = sriHash
		}
	}

	slogger.Info("Successfully calculated SRI hashes for static assets.")
	return nil
}

// initResolver sets up a custom DNS resolver if specified in the config.
// This is used for the malware protection feature.
func initResolver() {
	if !config.MalwareProtection.Enabled || len(config.MalwareProtection.CustomDNSServers) == 0 {
		return
	}

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}
	customResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Randomly select a DNS server from the list for each dial to improve resilience.
			server := config.MalwareProtection.CustomDNSServers[mrand.Intn(len(config.MalwareProtection.CustomDNSServers))]
			return dialer.DialContext(ctx, "udp", server)
		},
	}
	if slogger != nil {
		slogger.Info("Using custom DNS resolver for malware checks", "servers", config.MalwareProtection.CustomDNSServers)
	}
}

// findDataDir locates the data directory by searching in common locations.
// It prioritizes the directory next to the executable, then the current working directory.
func findDataDir(baseDirName string) (string, error) {
	// 1. Check for path relative to the executable
	exePath, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exePath)
		relPath := filepath.Join(exeDir, baseDirName)
		if _, err := os.Stat(relPath); err == nil {
			// Found it next to the executable
			return relPath, nil
		}
	}

	// 2. If not found, check the current working directory
	cwd, err := os.Getwd()
	if err == nil {
		cwdPath := filepath.Join(cwd, baseDirName)
		if _, err := os.Stat(cwdPath); err == nil {
			// Found it in the CWD
			return cwdPath, nil
		}
	}

	return "", fmt.Errorf("could not find data directory '%s' relative to executable or current working directory", baseDirName)
}

// generateSessionToken creates a cryptographically secure, random string to be used as a session token.
func generateSessionToken() (string, error) {
	// 32 bytes of entropy is a good standard for session tokens.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Encode to a URL-safe base64 string, which is cookie-friendly.
	return base64.URLEncoding.EncodeToString(b), nil
}

// generateRandomKey creates a random key of a given length from the allowed charset.
func generateRandomKey(length int) (string, error) {
	key := make([]byte, length)
	// Read random bytes
	if _, err := rand.Read(key); err != nil {
		return "", err
	}

	// Map random bytes to the charset
	for i := 0; i < length; i++ {
		key[i] = charset[int(key[i])%len(charset)]
	}

	return string(key), nil
}
