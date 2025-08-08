package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

// loadConfig reads the configuration from config.yaml and populates the config struct.
// It uses sync.Once to ensure this only happens once.
func loadConfig() (err error) {
	configOnce.Do(func() {
		localConfigPath := filepath.Join("shorterdata", "Config")
		defaultConfigPath := filepath.Join("shorterdata", "config.yaml")

		// Try to load the local override first.
		data, err := os.ReadFile(localConfigPath)
		if err != nil {
			// If local override fails, fall back to the default public config.
			data, err = os.ReadFile(defaultConfigPath)
			if err != nil {
				configErr = fmt.Errorf("failed to read both local config (%s) and default config (%s): %w", localConfigPath, defaultConfigPath, err)
				return
			}
			loadedConfigPath = defaultConfigPath
		} else {
			loadedConfigPath = localConfigPath
		}

		// Use UnmarshalStrict to error out on unknown fields in the config file.
		if err := yaml.UnmarshalStrict(data, &config); err != nil {
			configErr = fmt.Errorf("could not parse config file: %w", err)
			return
		}

		// Allow environment variables to override file settings.
		overrideConfigWithEnv()

		// If BaseDir is not set, try to find it automatically.
		if config.BaseDir == "" {
			dataPath, err := findDataDir("shorterdata")
			if err != nil {
				configErr = fmt.Errorf("BaseDir is not set and could not find 'shorterdata' directory: %w", err)
				return
			}
			config.BaseDir = dataPath
		}

		if len(config.DomainNames) == 0 {
			configErr = fmt.Errorf("at least one domain name must be specified in DomainNames")
			return
		}
		config.PrimaryDomain = config.DomainNames[0]

		if !filepath.IsAbs(config.BaseDir) {
			config.BaseDir = filepath.Join(".", config.BaseDir)
		}

		// Generate or load the HMAC secret.
		if err := setupHMAC(); err != nil {
			configErr = fmt.Errorf("failed to set up HMAC secret: %w", err)
			return
		}
	})
	return configErr
}

// overrideConfigWithEnv checks for environment variables and uses them to override
// settings from the config file. This is ideal for production environments like Render.
func overrideConfigWithEnv() {
	// On Render, the port is specified by the PORT environment variable.
	if renderPort := os.Getenv("PORT"); renderPort != "" {
		config.AddressPort = "0.0.0.0:" + renderPort
	}

	// On Render, the database URL is provided as an environment variable for security.
	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		config.DatabaseURL = dbURL
	}

	// On Render, the log separator can be provided as an environment variable for security.
	if logSep := os.Getenv("LOG_SEP"); logSep != "" {
		config.LogSep = logSep
	}

	// On Render, domain names can be provided as a comma-separated environment variable.
	if domainsStr := os.Getenv("SHORTER_DOMAINS"); domainsStr != "" {
		domains := strings.Split(domainsStr, ",")
		// Trim whitespace from each domain to handle "domain1, domain2" correctly.
		for i := range domains {
			domains[i] = strings.TrimSpace(domains[i])
		}
		config.DomainNames = domains
	}

	// On Render, admin credentials should be provided as environment variables.
	if adminUser := os.Getenv("ADMIN_USER"); adminUser != "" {
		config.Admin.User = adminUser
	}
	if adminPassHash := os.Getenv("ADMIN_PASS_HASH"); adminPassHash != "" {
		config.Admin.PassHash = adminPassHash
	}

	// Allow overriding FileUploadsEnabled via environment variable.
	if fileUploadsEnabled := os.Getenv("SHORTER_FILE_UPLOADS_ENABLED"); fileUploadsEnabled != "" {
		config.FileUploadsEnabled = strings.ToLower(fileUploadsEnabled) == "true"
	}
}

// setupHMAC ensures that a secret key for signing cookies is available.
// It tries to load it from an environment variable first, then from a file.
// If neither exists, it generates a new key and saves it to the file.
func setupHMAC() error {
	// 1. Try to load from environment variable (highest priority).
	hmacSecretStr := os.Getenv("SHORTER_HMAC_SECRET")
	if hmacSecretStr != "" {
		decoded, err := base64.StdEncoding.DecodeString(hmacSecretStr)
		if err != nil {
			return fmt.Errorf("failed to decode SHORTER_HMAC_SECRET from base64: %w", err)
		}
		config.hmacSecret = decoded
		return nil
	}

	// 2. If not in env, try to load from file.
	hmacFilePath := filepath.Join(config.BaseDir, "hmac_secret.key")
	key, err := os.ReadFile(hmacFilePath)
	if err == nil {
		config.hmacSecret = key
		return nil
	}

	// 3. If file doesn't exist, generate a new key.
	if os.IsNotExist(err) {
		newKey := make([]byte, 32) // 256 bits
		if _, err := rand.Read(newKey); err != nil {
			return fmt.Errorf("failed to generate new HMAC secret: %w", err)
		}
		config.hmacSecret = newKey

		// 4. Save the new key to the file for future use.
		if err := os.WriteFile(hmacFilePath, newKey, 0600); err != nil {
			return fmt.Errorf("failed to save new HMAC secret to %s: %w", hmacFilePath, err)
		}
		return nil
	}

	// 5. If there was some other error reading the file, return it.
	return fmt.Errorf("failed to read HMAC secret from %s: %w", hmacFilePath, err)
}

