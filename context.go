package main

import (
	"context"
	"net/http"
)

// contextKey is a custom type to avoid key collisions in context.
type contextKey string

const userContextKey = contextKey("user")

// setUserInContext adds the user object to the request context.
func setUserInContext(r *http.Request, user *User) *http.Request {
	ctx := context.WithValue(r.Context(), userContextKey, user)
	return r.WithContext(ctx)
}

// getUserFromContext retrieves the user object from the request context.
func getUserFromContext(r *http.Request) *User {
	user, _ := r.Context().Value(userContextKey).(*User)
	return user
}
