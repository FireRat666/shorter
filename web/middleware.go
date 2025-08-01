package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
)

// A private key type to use for context values. This prevents collisions.
type contextKey string

// NonceContextKey is the key used to store the CSP nonce in the request context.
const NonceContextKey = contextKey("nonce")

// generateNonce creates a cryptographically secure random string for use as a CSP nonce.
func generateNonce() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// CspAdminMiddleware sets a strict Content-Security-Policy for all admin-related pages.
// It generates a nonce for each request to allow specific inline scripts to run securely.
func CspAdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce, err := generateNonce()
		if err != nil {
			http.Error(w, "Failed to generate security token", http.StatusInternalServerError)
			return
		}

		// Define the Content Security Policy, including the nonce for scripts.
		csp := fmt.Sprintf(
			"default-src 'self'; style-src 'self' https://*.hcaptcha.com; script-src 'self' 'nonce-%s' https://cdn.jsdelivr.net https://*.hcaptcha.com; connect-src 'self' https://*.hcaptcha.com; form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'; report-uri /csp-report;",
			nonce,
		)
		w.Header().Set("Content-Security-Policy", csp)

		// Add the nonce to the request's context so handlers can access it.
		ctx := context.WithValue(r.Context(), NonceContextKey, nonce)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
