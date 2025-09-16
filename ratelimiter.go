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
	every    time.Duration // The "Every" duration used to create the limiter.
}

// clientXY represents a user for the X-in-Y rate limiting.
type clientXY struct {
	requests []time.Time
	lastSeen time.Time
}

var (
	// clients map for IP-based rate limiting (anonymous users)
	ipClients = make(map[string]*client)
	ipMu      sync.Mutex

	// clients map for the first X-in-Y rate limiter
	ipClientsXY1 = make(map[string]*clientXY)
	ipMuXY1      sync.Mutex

	// clients map for the second X-in-Y rate limiter
	ipClientsXY2 = make(map[string]*clientXY)
	ipMuXY2      sync.Mutex

	// clients map for token-based rate limiting (API users)
	tokenClients = make(map[string]*client)
	tokenMu      sync.Mutex
)

// // isRateLimitedXY checks if an IP is rate-limited based on an X-in-Y configuration.
func isRateLimitedXY(ip string, config *RateLimitXYConfig, clients map[string]*clientXY, mu *sync.Mutex) bool {
	if config == nil || !config.Enabled || config.X <= 0 || config.Y == "" {
		return false // Not rate limited if disabled or misconfigured
	}

	mu.Lock()
	defer mu.Unlock()

	duration, err := time.ParseDuration(config.Y)
	if err != nil {
		slogger.Error("Invalid RateLimitXY.Y format", "duration", config.Y, "error", err)
		return false // Do not block on config error
	}

	// Get or create client
	client, found := clients[ip]
	if !found {
		client = &clientXY{}
		clients[ip] = client
	}
	client.lastSeen = time.Now()

	// Remove old requests that are outside the time window
	now := time.Now()
	var recentRequests []time.Time
	for _, t := range client.requests {
		if now.Sub(t) < duration {
			recentRequests = append(recentRequests, t)
		}
	}
	client.requests = recentRequests

	// Check if the number of recent requests exceeds the limit
	if len(client.requests) >= config.X {
		return true // Rate limited
	}

	// Add the current request timestamp
	client.requests = append(client.requests, now)

	return false // Not rate limited
}

// getAnonymousClientByIP returns the rate limiter for a given IP address and anonymous rate limit configuration.
func getAnonymousClientByIP(ip string, anonRateLimitCfg *AnonymousRateLimitConfig) *rate.Limiter {
	ipMu.Lock()
	defer ipMu.Unlock()

	// If anonRateLimitCfg is nil or disabled, we don't need to rate limit.
	// We also remove any existing client for this IP to handle cases where
	// rate limiting was disabled after being enabled.
	if anonRateLimitCfg == nil || !anonRateLimitCfg.Enabled {
		delete(ipClients, ip)
		return rate.NewLimiter(rate.Inf, 0)
	}

	// Parse the duration from the config.
	duration, err := time.ParseDuration(anonRateLimitCfg.Every)
	if err != nil {
		slogger.Error("Invalid AnonymousRateLimit.Every format, using 30s default", "duration", anonRateLimitCfg.Every, "error", err)
		duration = 30 * time.Second
	}

	// Check if a client already exists for this IP.
	if c, found := ipClients[ip]; found {
		// If the configured duration has changed, create a new limiter.
		if c.every != duration {
			newLimiter := rate.NewLimiter(rate.Every(duration), 1)
			c.limiter = newLimiter
			c.every = duration
			slogger.Info("Anonymous rate limit updated for IP", "ip", ip, "new_duration", duration)
		}
		c.lastSeen = time.Now()
		return c.limiter
	}

	// If no client was found, create a new one.
	limiter := rate.NewLimiter(rate.Every(duration), 1)
	ipClients[ip] = &client{
		limiter:  limiter,
		lastSeen: time.Now(),
		every:    duration,
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
// from all maps to prevent them from growing indefinitely.
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

		// Clean up IP-based XY clients (limiter 1)
		ipMuXY1.Lock()
		for ip, c := range ipClientsXY1 {
			if time.Since(c.lastSeen) > 15*time.Minute {
				delete(ipClientsXY1, ip)
			}
		}
		ipMuXY1.Unlock()

		// Clean up IP-based XY clients (limiter 2)
		ipMuXY2.Lock()
		for ip, c := range ipClientsXY2 {
			if time.Since(c.lastSeen) > 15*time.Minute {
				delete(ipClientsXY2, ip)
			}
		}
		ipMuXY2.Unlock()

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
func anonymousRateLimitMiddleware(anonRateLimitCfg *AnonymousRateLimitConfig, rateLimit1 *RateLimitXYConfig, rateLimit2 *RateLimitXYConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			slogger.Error("Could not get IP for rate limiting", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Check the standard anonymous rate limiter first.
		limiter := getAnonymousClientByIP(ip, anonRateLimitCfg)
		if !limiter.Allow() {
			handleRateLimitExceeded(w, r)
			return
		}

		// Check the first X-in-Y rate limiter.
		if isRateLimitedXY(ip, rateLimit1, ipClientsXY1, &ipMuXY1) {
			handleRateLimitExceeded(w, r)
			return
		}

		// Check the second X-in-Y rate limiter.
		if isRateLimitedXY(ip, rateLimit2, ipClientsXY2, &ipMuXY2) {
			handleRateLimitExceeded(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleRateLimitExceeded sends the appropriate "429 Too Many Requests" response.
func handleRateLimitExceeded(w http.ResponseWriter, r *http.Request) {
	userAgent := strings.ToLower(r.UserAgent())
	isCLI := strings.Contains(userAgent, "curl") || strings.Contains(userAgent, "wget") || strings.Contains(userAgent, "powershell")

	if isCLI {
		// For command-line tools, send a simple text response.
		http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
	} else {
		// For browsers, use the themed error page.
		logErrors(w, r, "You are making too many requests. Please wait a moment and try again.", http.StatusTooManyRequests, "Rate limit exceeded for anonymous user")
	}
}
