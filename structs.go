package main

import (
	"crypto/rand"
	"time"
)

// Config holds all the configuration for the application, read from the config file.
type Config struct {
	DomainNames              []string                   `yaml:"DomainNames"`
	PrimaryDomain            string                     // Set programmatically
	AddressPort              string                     `yaml:"AddressPort"`
	BaseDir                  string                     `yaml:"BaseDir"`
	DatabaseURL              string                     `yaml:"DatabaseURL"`
	Logging                  bool                       `yaml:"Logging"`
	LogLevel                 string                     `yaml:"LogLevel"`
	Logfile                  string                     `yaml:"Logfile"`
	LogSep                   string                     `yaml:"LogSep"`
	MaxKeyLen                int                        `yaml:"MaxKeyLen"`
	LinkLen1                 int                        `yaml:"LinkLen1"`
	LinkLen2                 int                        `yaml:"LinkLen2"`
	LinkLen3                 int                        `yaml:"LinkLen3"`
	MaxFileSize              int64                      `yaml:"MaxFileSize"`
	MinSizeToGzip            int                        `yaml:"MinSizeToGzip"`
	LowRAM                   bool                       `yaml:"LowRAM"`
	SessionTimeout           string                     `yaml:"SessionTimeout"`
	SessionTimeoutRememberMe string                     `yaml:"SessionTimeoutRememberMe"`
	CleanupInterval          string                     `yaml:"CleanupInterval"`
	CSP                      string                     `yaml:"CSP"`
	Admin                    AdminConfig                `yaml:"Admin"`
	MalwareProtection        MalwareProtectionConfig    `yaml:"MalwareProtection"`
	Defaults                 SubdomainConfig            `yaml:"Defaults"`
	Subdomains               map[string]SubdomainConfig `yaml:"Subdomains"`
}

// AdminConfig holds the admin user credentials.
type AdminConfig struct {
	User     string `yaml:"User"`
	PassHash string `yaml:"PassHash"`
}

// MalwareProtectionConfig holds settings for DNSBL checks.
type MalwareProtectionConfig struct {
	Enabled          bool     `yaml:"Enabled"`
	DNSBLServers     []string `yaml:"DNSBLServers"`
	CustomDNSServers []string `yaml:"CustomDNSServers"`
}

// SubdomainConfig holds settings that can be applied globally or per-subdomain.
type SubdomainConfig struct {
	LinkLen1Timeout string            `yaml:"LinkLen1Timeout,omitempty"`
	LinkLen1Display string            `yaml:"LinkLen1Display,omitempty"`
	LinkLen2Timeout string            `yaml:"LinkLen2Timeout,omitempty"`
	LinkLen2Display string            `yaml:"LinkLen2Display,omitempty"`
	LinkLen3Timeout string            `yaml:"LinkLen3Timeout,omitempty"`
	LinkLen3Display string            `yaml:"LinkLen3Display,omitempty"`
	CustomTimeout   string            `yaml:"CustomTimeout,omitempty"`
	CustomDisplay   string            `yaml:"CustomDisplay,omitempty"`
	LinkAccessMaxNr int               `yaml:"LinkAccessMaxNr,omitempty"`
	StaticLinks     map[string]string `yaml:"StaticLinks,omitempty"`
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

// Session represents a user's login session in the database.
type Session struct {
	Token     string
	UserID    string
	ExpiresAt time.Time
}

type showLinkVars struct {
	Domain        string
	Data          string
	Timeout       string
	TimesAllowed  int
	RemainingUses int
	CssSRIHash    string
}

type showTextVars struct {
	Domain            string
	Data              string
	Timeout           string
	TimesAllowed      int
	RemainingUses     int
	ShowTextJsSRIHash string
	CssSRIHash        string
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
	CssSRIHash string
}

// loginPageVars holds data for the login page template.
type loginPageVars struct {
	CssSRIHash string
	Error      string
}

// adminPageVars holds the data for the main admin dashboard.
type adminPageVars struct {
	Subdomains          map[string]SubdomainConfig
	PrimaryDomainConfig SubdomainConfig
	Defaults            SubdomainConfig
	PrimaryDomain       string
	CssSRIHash          string
	AdminJsSRIHash      string
}

// adminEditPageVars holds the data for the subdomain edit page.
type adminEditPageVars struct {
	Domain         string
	Config         SubdomainConfig
	Defaults       SubdomainConfig
	Links          []Link
	CssSRIHash     string
	AdminJsSRIHash string
}

// adminEditStaticLinkPageVars holds the data for the static link edit page.
type adminEditStaticLinkPageVars struct {
	Domain      string
	Key         string
	Destination string
	CssSRIHash  string
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
