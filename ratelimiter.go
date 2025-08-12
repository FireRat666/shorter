package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// client represents a user for rate limiting purposes.
type client struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

var (
	// clients map for IP-based rate limiting (anonymous users)
	ipClients = make(map[string]*client)
	ipMu      sync.Mutex

	// clients map for token-based rate limiting (API users)
	tokenClients = make(map[string]*client)
	tokenMu      sync.Mutex
)

// getAnonymousClientByIP returns the rate limiter for a given IP address and anonymous rate limit configuration.
func getAnonymousClientByIP(ip string, anonRateLimitCfg *AnonymousRateLimitConfig) *rate.Limiter {
	ipMu.Lock()
	defer ipMu.Unlock()

	// Use a composite key for the map to differentiate between different rate limit configurations
	// for the same IP, though for anonymous users, the config should be consistent per domain.
	// For simplicity, we'll still use just the IP as the key, assuming the middleware
	// ensures the correct config is passed.
	if c, found := ipClients[ip]; found {
		c.lastSeen = time.Now()
		return c.limiter
	}

	// If anonRateLimitCfg is nil (e.g., if the config was not loaded or subdomain config is missing),
	// use a default safe rate limit.
	if anonRateLimitCfg == nil || !anonRateLimitCfg.Enabled {
		// If rate limiting is disabled or config is missing, return a limiter that always allows.
		// This effectively bypasses rate limiting for this IP.
		limiter := rate.NewLimiter(rate.Inf, 0) // Infinite rate, 0 burst
		ipClients[ip] = &client{
			limiter:  limiter,
			lastSeen: time.Now(),
		}
		return limiter
	}

	// Create a new limiter based on the "Every" duration from the provided config.
	duration, err := time.ParseDuration(anonRateLimitCfg.Every)
	if err != nil {
		// Fallback to a safe default if config is invalid.
		slogger.Error("Invalid AnonymousRateLimit.Every format, using 30s default", "duration", anonRateLimitCfg.Every, "error", err)
		duration = 30 * time.Second
	}
	// The burst is 1, meaning they can make one request, then must wait for the 'Every' duration.
	limiter := rate.NewLimiter(rate.Every(duration), 1)

	ipClients[ip] = &client{
		limiter:  limiter,
		lastSeen: time.Now(),
	}
	return limiter
}

// getClientByToken returns the rate limiter for a given API token.
func getClientByToken(token string) *rate.Limiter {
	tokenMu.Lock()
	defer tokenMu.Unlock()

	if c, found := tokenClients[token]; found {
		c.lastSeen = time.Now()
		return c.limiter
	}

	limiter := rate.NewLimiter(rate.Limit(config.APIRateLimit.Rate), config.APIRateLimit.Burst)
	tokenClients[token] = &client{
		limiter:  limiter,
		lastSeen: time.Now(),
	}
	return limiter
}

// cleanupClients is a background goroutine that removes old, inactive clients
// from both maps to prevent them from growing indefinitely.
func cleanupClients() {
	for {
		time.Sleep(10 * time.Minute)

		// Clean up IP-based clients
		ipMu.Lock()
		for ip, c := range ipClients {
			if time.Since(c.lastSeen) > 15*time.Minute {
				delete(ipClients, ip)
			}
		}
		ipMu.Unlock()

		// Clean up token-based clients
		tokenMu.Lock()
		for token, c := range tokenClients {
			if time.Since(c.lastSeen) > 15*time.Minute {
				delete(tokenClients, token)
			}
		}
		tokenMu.Unlock()
	}
}

// anonymousRateLimitMiddleware is a middleware that enforces rate limiting for anonymous users.
func anonymousRateLimitMiddleware(anonRateLimitCfg *AnonymousRateLimitConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The check for anonRateLimitCfg.Enabled is now handled within getAnonymousClientByIP,
		// which correctly considers if rate limiting is enabled for the specific subdomain.
		// The global config.AnonymousRateLimit.Enabled check is removed here to allow
		// subdomain-specific rate limit configurations to take precedence.


		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			slogger.Error("Could not get IP for rate limiting", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		limiter := getAnonymousClientByIP(ip, anonRateLimitCfg)
		if !limiter.Allow() {
			// Rate limit exceeded. Check the user agent to provide the appropriate response.
			userAgent := strings.ToLower(r.UserAgent())
			isCLI := strings.Contains(userAgent, "curl") || strings.Contains(userAgent, "wget") || strings.Contains(userAgent, "powershell")

			if isCLI {
				// For command-line tools, send a simple text response.
				http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
			} else {
				// For browsers, use the themed error page.
				logErrors(w, r, "You are making too many requests. Please wait a moment and try again.", http.StatusTooManyRequests, "Rate limit exceeded for anonymous user")
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

