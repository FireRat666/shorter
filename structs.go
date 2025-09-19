package main

import (
	"database/sql"
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
	MaxRequestSize           int64                      `yaml:"MaxRequestSize"`
	MaxURLSize               int                        `yaml:"MaxURLSize"`
	MaxTextSize              int                        `yaml:"MaxTextSize"`
	MinSizeToGzip            int                        `yaml:"MinSizeToGzip"`
	LowRAM                   bool                       `yaml:"LowRAM"`
	SessionTimeout           string                     `yaml:"SessionTimeout"`
	FileUploadsEnabled       bool                       `yaml:"FileUploadsEnabled"`
	SessionTimeoutRememberMe string                     `yaml:"SessionTimeoutRememberMe"`
	CleanupInterval          string                     `yaml:"CleanupInterval"`
	CSP                      string                     `yaml:"CSP"`
	AbuseReporting           AbuseReportingConfig       `yaml:"AbuseReporting"`
	AnonymousRateLimit       AnonymousRateLimitConfig   `yaml:"AnonymousRateLimit"`
	APIRateLimit             APIRateLimitConfig         `yaml:"APIRateLimit"`
	Admin                    AdminConfig                `yaml:"Admin"`
	MalwareProtection        MalwareProtectionConfig    `yaml:"MalwareProtection"`
	Defaults                 SubdomainConfig            `yaml:"Defaults"`
	Subdomains               map[string]SubdomainConfig `yaml:"Subdomains"`
	hmacSecret               []byte                     // Set programmatically
}

// AdminConfig holds the admin user credentials.
type AdminConfig struct {
	User        string `yaml:"User"`
	TOTPEnabled bool   `yaml:"TOTPEnabled"`
	TOTPSecret  string `yaml:"TOTPSecret"`
	PassHash    string `yaml:"PassHash"`
}

// MalwareProtectionConfig holds settings for DNSBL checks.
type MalwareProtectionConfig struct {
	Enabled          bool     `yaml:"Enabled"`
	DNSBLServers     []string `yaml:"DNSBLServers"`
	CustomDNSServers []string `yaml:"CustomDNSServers"`
}

// AbuseReportingConfig holds settings for the abuse reporting feature.
type AbuseReportingConfig struct {
	Enabled  bool           `yaml:"Enabled"`
	HCaptcha HCaptchaConfig `yaml:"hCaptcha"`
}

// HCaptchaConfig holds the site key and secret key for the hCaptcha service.
type HCaptchaConfig struct {
	SiteKey   string `yaml:"SiteKey"`
	SecretKey string `yaml:"SecretKey"`
}

// hCaptchaVerifyResponse is the expected JSON response from the hCaptcha API.
type hCaptchaVerifyResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"` // ISO8601 timestamp
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
}

// AnonymousRateLimitConfig holds settings for anonymous user rate limiting.
type AnonymousRateLimitConfig struct {
	Enabled bool   `yaml:"Enabled"`
	Every   string `yaml:"Every"` // e.g., "30s", "1m"
}

// APIRateLimitConfig holds settings for the API rate limiter.
type APIRateLimitConfig struct {
	Enabled bool    `yaml:"Enabled"`
	Rate    float64 `yaml:"Rate"`  // Requests per second
	Burst   int     `yaml:"Burst"` // Maximum burst size
}

// RateLimitXYConfig holds settings for X actions in Y time rate limiting.
type RateLimitXYConfig struct {
	Enabled bool   `yaml:"Enabled"`
	X       int    `yaml:"X"` // How many actions
	Y       string `yaml:"Y"` // In what time frame
}

// SubdomainConfig holds settings that can be applied globally or per-subdomain.
type SubdomainConfig struct {
	LinkLen1           int                       `yaml:"LinkLen1,omitempty"`
	LinkLen2           int                       `yaml:"LinkLen2,omitempty"`
	LinkLen3           int                       `yaml:"LinkLen3,omitempty"`
	MaxKeyLen          int                       `yaml:"MaxKeyLen,omitempty"`
	MaxRequestSize     int64                     `yaml:"MaxRequestSize,omitempty"`
	MaxTextSize        int                       `yaml:"MaxTextSize,omitempty"`
	MinSizeToGzip      int                       `yaml:"MinSizeToGzip,omitempty"`
	FileUploadsEnabled *bool                     `yaml:"FileUploadsEnabled,omitempty"`
	AnonymousRateLimit *AnonymousRateLimitConfig `yaml:"AnonymousRateLimit,omitempty"`
	RateLimit1         *RateLimitXYConfig        `yaml:"RateLimit1,omitempty"`
	RateLimit2         *RateLimitXYConfig        `yaml:"RateLimit2,omitempty"`
	LinkLen1Timeout    string                    `yaml:"LinkLen1Timeout,omitempty"`
	LinkLen1Display    string                    `yaml:"LinkLen1Display,omitempty"`
	LinkLen2Timeout    string                    `yaml:"LinkLen2Timeout,omitempty"`
	LinkLen2Display    string                    `yaml:"LinkLen2Display,omitempty"`
	LinkLen3Timeout    string                    `yaml:"LinkLen3Timeout,omitempty"`
	LinkLen3Display    string                    `yaml:"LinkLen3Display,omitempty"`
	CustomTimeout      string                    `yaml:"CustomTimeout,omitempty"`
	CustomDisplay      string                    `yaml:"CustomDisplay,omitempty"`
	LinkAccessMaxNr    int                       `yaml:"LinkAccessMaxNr,omitempty"`
	StaticLinks        map[string]string         `yaml:"StaticLinks,omitempty"`
}

// Link represents a shortened link record in the database.
type Link struct {
	Key          string
	Domain       string
	LinkType     string
	Data         []byte
	IsCompressed bool
	PasswordHash sql.NullString
	CreatedBy    sql.NullString // UserID of the creator
	TimesAllowed int
	TimesUsed    int
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

// Session represents a user's login session in the database.
type Session struct {
	Token     string
	UserID    string
	CSRFToken string
	ExpiresAt time.Time
}

// APIKey represents a user's API key in the database.
type APIKey struct {
	Token       string
	UserID      string
	Description string
	CreatedAt   time.Time
}

type linkCreatedPageVars struct {
	Domain         string
	DestinationURL string
	ShortURL       string
	QRCodeURL      string
	Timeout        string
	TimesAllowed   int
	RemainingUses  int
	KeyExtended    bool
	CssSRIHash     string
}

type textDumpCreatedPageVars struct {
	Domain        string
	ShortURL      string
	Timeout       string
	TimesAllowed  int
	RemainingUses int
	KeyExtended   bool
	CssSRIHash    string
}

type fileCreatedPageVars struct {
	Domain        string
	ShortURL      string
	Timeout       string
	TimesAllowed  int
	RemainingUses int
	KeyExtended   bool
	CssSRIHash    string
}

type showFilePageVars struct {
	Domain         string
	Key            string
	FileName       string
	FileSize       string // Formatted string like "123 KB"
	DownloadURL    string
	Timeout        string
	TimesAllowed   int
	RemainingUses  int
	AbuseReporting AbuseReportingConfig
	CssSRIHash     string
}

type showRedirectPageVars struct {
	Domain         string
	Key            string
	DestinationURL string
	Timeout        string
	TimesAllowed   int
	RemainingUses  int
	AbuseReporting AbuseReportingConfig
	CssSRIHash     string
	OGTitle        string
	OGDescription  string
	OGImage        string
	OGUrl          string
}

type showTextVars struct {
	Domain            string
	Key               string
	Data              string
	Timeout           string
	TimesAllowed      int
	RemainingUses     int
	AbuseReporting    AbuseReportingConfig
	ShowTextJsSRIHash string
	CssSRIHash        string
}

// AbuseReport represents a single abuse report record from the database.
type AbuseReport struct {
	ID            int64
	LinkKey       string
	LinkDomain    string
	ReporterEmail string
	Comments      string
	Status        string
	ReportedAt    time.Time
}

// IndexPageVars holds the data needed to render the index page template.
type IndexPageVars struct {
	CssSRIHash         string
	IndexJsSRIHash     string
	LinkLen1Display    string
	LinkLen2Display    string
	LinkLen3Display    string
	CustomDisplay      string
	LinkAccessMaxNr    int
	MaxURLSize         int
	FileUploadsEnabled bool
	MaxTextSize        int
	MaxFileSize        string
	CSRFToken          string
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
	CSRFToken  string
}

// passwordPromptPageVars holds data for the password prompt page.
type passwordPromptPageVars struct {
	Key        string
	Error      string
	CSRFToken  string
	CssSRIHash string
}

// adminPageVars holds the data for the main admin dashboard.
type adminPageVars struct {
	Subdomains          map[string]SubdomainConfig
	PrimaryDomainConfig SubdomainConfig
	Defaults            SubdomainConfig
	PrimaryDomain       string
	CssSRIHash          string
	AdminJsSRIHash      string
	TotalLinks          int
	TotalClicks         int
	CSRFToken           string
}

// LinkStats holds a comprehensive set of statistics for the analytics page.
type LinkStats struct {
	TotalActiveLinks        int
	TotalLinksCreated       int
	TotalClicks             int
	LinksCreatedLastHour    int
	LinksCreatedLast24Hours int
	LinksCreatedLast7Days   int
	LinksExpiredLastHour    int
	LinksExpiredLast24Hours int
	LinksExpiredLast7Days   int
	ClicksLastHour          int
	ClicksLast24Hours       int
	ClicksLast7Days         int
}

// statsPageVars holds the data for the statistics page template.
type statsPageVars struct {
	CssSRIHash string
	Nonce      string // For Content-Security-Policy
	CSRFToken  string
}

// CreatorStats holds statistics for a single link creator.
type CreatorStats struct {
	UserID    string
	LinkCount int
}

// DomainStats holds statistics for a single domain.
type DomainStats struct {
	Domain      string
	ActiveLinks int
	TotalClicks int
}

// adminEditPageVars holds the data for the subdomain edit page.
type adminEditPageVars struct {
	Domain         string
	Config         SubdomainConfig
	Defaults       SubdomainConfig
	Links          []Link
	CssSRIHash     string
	AdminJsSRIHash string
	CurrentPage    int
	TotalPages     int
	HasPrev        bool
	HasNext        bool
	SearchQuery    string
	CSRFToken      string
}

// adminEditStaticLinkPageVars holds the data for the static link edit page.
type adminEditStaticLinkPageVars struct {
	Domain      string
	Key         string
	Destination string
	CSRFToken   string
	CssSRIHash  string
}

// adminEditLinkPageVars holds the data for the dynamic link edit page.
type adminEditLinkPageVars struct {
	Link       Link
	DataString string // The link's data, decompressed if necessary.
	CSRFToken  string
	CssSRIHash string
}

// adminAbuseReportsPageVars holds data for the abuse reports management page.
type adminAbuseReportsPageVars struct {
	Reports     []AbuseReport
	CurrentPage int
	TotalPages  int
	HasPrev     bool
	HasNext     bool
	SearchQuery string
	Filter      string
	CssSRIHash  string
	Nonce       string
	CSRFToken   string
}

// adminAPIKeysPageVars holds data for the API key management page.
type adminAPIKeysPageVars struct {
	APIKeys        []APIKey
	NewKey         string // To display a newly generated key
	AdminJsSRIHash string
	CssSRIHash     string
	CurrentPage    int
	TotalPages     int
	HasPrev        bool
	HasNext        bool
	SearchQuery    string
	CSRFToken      string
}

// apiCreateLinkRequest defines the structure for a JSON request to create a new link via the API.
type apiCreateLinkRequest struct {
	URL       string `json:"url"`
	Domain    string `json:"domain,omitempty"`     // Optional. If not provided, use PrimaryDomain.
	ExpiresIn string `json:"expires_in,omitempty"` // Optional. e.g., "1h", "30m". If not provided, use a default.
	MaxUses   int    `json:"max_uses,omitempty"`   // Optional.
	Password  string `json:"password,omitempty"`   // Optional.
	CustomKey string `json:"custom_key,omitempty"` // Optional.
}

// apiCreateLinkResponse defines the structure for a successful JSON response after creating a link.
type apiCreateLinkResponse struct {
	ShortURL  string    `json:"short_url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// apiUpdateLinkRequest defines the structure for a JSON request to update a link via the API.
// Key and Domain identify the link. Other fields are optional updates.
type apiUpdateLinkRequest struct {
	Key       string `json:"key"`
	Domain    string `json:"domain,omitempty"`
	ExpiresIn string `json:"expires_in,omitempty"` // e.g., "24h", "7d"
	MaxUses   *int   `json:"max_uses,omitempty"`   // Pointer to distinguish 0 from not-set
	Password  string `json:"password,omitempty"`   // Set a new password.
}

// apiDeleteLinkRequest defines the structure for a JSON request to delete a link via the API.
type apiDeleteLinkRequest struct {
	Key    string `json:"key"`
	Domain string `json:"domain,omitempty"` // Optional. If not provided, use PrimaryDomain.
}

// apiGetLinkResponse defines the structure for a successful JSON response when getting a link's details.
type apiGetLinkResponse struct {
	Key          string    `json:"key"`
	Domain       string    `json:"domain"`
	LinkType     string    `json:"link_type"`
	Data         string    `json:"data"` // For "url" and "text" types. Filename for "file" type.
	HasPassword  bool      `json:"has_password"`
	CreatedBy    string    `json:"created_by"`
	TimesAllowed int       `json:"times_allowed"`
	TimesUsed    int       `json:"times_used"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
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
