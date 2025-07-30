package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"time"
)

// calculateSRIHashes reads static assets (CSS, JS), computes their SRI hashes,
// and populates the global variables. This is called at startup.
func calculateSRIHashes() error {
	// shorter.css
	cssBytes, err := os.ReadFile(filepath.Join(config.BaseDir, "css", "shorter.css"))
	if err != nil {
		return fmt.Errorf("failed to read shorter.css: %w", err)
	}
	cssHash := sha256.Sum256(cssBytes)
	cssSRIHash = "sha256-" + base64.StdEncoding.EncodeToString(cssHash[:])

	// admin.js - This is optional, so we don't return an error if it's missing.
	adminJsBytes, err := os.ReadFile(filepath.Join(config.BaseDir, "js", "admin.js"))
	if err == nil {
		adminHash := sha256.Sum256(adminJsBytes)
		adminJsSRIHash = "sha256-" + base64.StdEncoding.EncodeToString(adminHash[:])
	} else {
		slogger.Warn("admin.js not found, skipping SRI hash calculation for it.")
	}

	// showText.js - This is also optional.
	showTextJsBytes, err := os.ReadFile(filepath.Join(config.BaseDir, "js", "showText.js"))
	if err == nil {
		showTextHash := sha256.Sum256(showTextJsBytes)
		showTextJsSRIHash = "sha256-" + base64.StdEncoding.EncodeToString(showTextHash[:])
	} else {
		slogger.Warn("showText.js not found, skipping SRI hash calculation for it.")
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
			server := config.MalwareProtection.CustomDNSServers[rand.Intn(len(config.MalwareProtection.CustomDNSServers))]
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
