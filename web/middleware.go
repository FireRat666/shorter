package web

import (
	"net/http"
)

// CspAdminMiddleware adds a strict Content-Security-Policy header suitable for admin pages.
// It helps prevent XSS and other injection attacks by restricting where content can be loaded from.
func CspAdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This policy allows resources (scripts, styles) only from the same origin ('self'),
		// blocks the page from being iframed, and restricts form submissions to the same origin.
		csp := "default-src 'self'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none';"
		w.Header().Set("Content-Security-Policy", csp)
		next.ServeHTTP(w, r)
	})
}
