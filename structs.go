package main

import (
	"crypto/rand"
	"time"
)

// SubdomainConfig holds settings that can be overridden on a per-subdomain basis.
type SubdomainConfig struct {
	StaticLinks     map[string]string `yaml:"StaticLinks"`
	LinkLen1Timeout string            `yaml:"LinkLen1Timeout"`
	LinkLen2Timeout string            `yaml:"LinkLen2Timeout"`
	LinkLen3Timeout string            `yaml:"LinkLen3Timeout"`
	CustomTimeout   string            `yaml:"CustomTimeout"`
	LinkLen1Display string            `yaml:"LinkLen1Display"`
	LinkLen2Display string            `yaml:"LinkLen2Display"`
	LinkLen3Display string            `yaml:"LinkLen3Display"`
	CustomDisplay   string            `yaml:"CustomDisplay"`
	LinkAccessMaxNr int               `yaml:"LinkAccessMaxNr"`
	// You could add more overrides here, like a custom theme or logo path.
}

// MalwareProtectionConfig holds settings for the blocklist-based malware protection.
type MalwareProtectionConfig struct {
	Enabled          bool     `yaml:"Enabled"`
	DNSBLServers     []string `yaml:"DNSBLServers"`
	CustomDNSServers []string `yaml:"CustomDNSServers"`
}

// AdminConfig holds credentials for the secure admin interface.
type AdminConfig struct {
	User     string `yaml:"User"`
	PassHash string `yaml:"PassHash"` // Store bcrypt hash, not plaintext
}

// Config holds all the configuration for the application, read from the config file.
type Config struct {
	AddressPort       string                  `yaml:"AddressPort"`
	DomainNames       []string                `yaml:"DomainNames"`
	BaseDir           string                  `yaml:"BaseDir"`
	DatabaseURL       string                  `yaml:"DatabaseURL"`
	Logging           bool                    `yaml:"Logging"`
	Logfile           string                  `yaml:"Logfile"`
	LogSep            string                  `yaml:"LogSep"`
	MaxKeyLen         int                     `yaml:"MaxKeyLen"`
	LinkLen1          int                     `yaml:"LinkLen1"`
	LinkLen2          int                     `yaml:"LinkLen2"`
	LinkLen3          int                     `yaml:"LinkLen3"`
	MaxFileSize       int64                   `yaml:"MaxFileSize"`
	MinSizeToGzip     int                     `yaml:"MinSizeToGzip"`
	LowRAM            bool                    `yaml:"LowRAM"`
	CSP               string                  `yaml:"CSP"`
	Admin             AdminConfig             `yaml:"Admin"`
	MalwareProtection MalwareProtectionConfig `yaml:"MalwareProtection"`
	// Default settings will be used if a subdomain doesn't specify its own.
	Defaults   SubdomainConfig            `yaml:"Defaults"`
	Subdomains map[string]SubdomainConfig `yaml:"Subdomains"`
}

// Link represents a shortened link record in the database.
type Link struct {
	Key          string
	Domain       string
	LinkType     string
	Data         []byte
	IsCompressed bool
	TimesAllowed int
	TimesUsed    int
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

type showLinkVars struct {
	Domain        string
	Data          string
	Timeout       string
	TimesAllowed  int
	RemainingUses int
}

type showTextVars struct {
	Domain        string
	Data          string
	Timeout       string
	TimesAllowed  int
	RemainingUses int
}

// IndexPageVars holds the data needed to render the index page template.
type IndexPageVars struct {
	CssSRIHash      string
	LinkLen1Display string
	LinkLen2Display string
	LinkLen3Display string
	CustomDisplay   string
	LinkAccessMaxNr int
}

// errorPageVars holds the data needed to render a generic error page.
type errorPageVars struct {
	StatusCode int
	Message    string
}

// adminPageVars holds the data needed to render the admin page.
type adminPageVars struct {
	Subdomains map[string]SubdomainConfig
	Defaults   SubdomainConfig
}

// CSPReport represents the structure of a CSP violation report sent by the browser.
type CSPReport struct {
	CSPReport struct {
		DocumentURI        string `json:"document-uri"`
		Referrer           string `json:"referrer"`
		ViolatedDirective  string `json:"violated-directive"`
		EffectiveDirective string `json:"effective-directive"`
		OriginalPolicy     string `json:"original-policy"`
		BlockedURI         string `json:"blocked-uri"`
		StatusCode         int    `json:"status-code"`
	} `json:"csp-report"`
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
