package main

import (
	"html/template"
)

const (
	// charset consists of alphanumeric characters with some characters removed due to them being to similar in some fonts.
	charset = "abcdefghijkmnopqrstuvwxyz23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	// charset consists of characters that are valid for custom keys.
	customKeyCharset = "abcdefghijklmnopqrstuvwxyzåäö0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZÅÄÖ-_"
	// errServerError contains the generic error message users will se when somthing goes wrong
	errServerError      = "Internal Server Error"
	errInvalidKey       = "Invalid key"
	errInvalidKeyUsed   = "Invalid key, key is already in use"
	errInvalidCustomKey = "Invalid Custom Key was provided, valid characters are:\n" + customKeyCharset
	errNotImplemented   = "Not Implemented"
	errLowRAM           = "No Space available, new space will be available as old links become invalid"
)

var (
	// ImageMap is used in handlers.go to map requests to imagedata
	ImageMap map[string][]byte

	// SRI hashes will be populated at startup.
	// IMPORTANT: These are placeholder values. The application calculates the real hashes at startup.
	cssSRIHash        = "sha256-placeholder"
	adminJsSRIHash    = "sha256-placeholder"
	showTextJsSRIHash = "sha256-placeholder"

	templateMap map[string]*template.Template
)
