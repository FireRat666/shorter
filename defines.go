package main

const (
	// charset consists of alphanumeric characters with some characters removed due to them being to similar in some fonts.
	charset = "abcdefghijkmnopqrstuvwxyz23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	// charset consists of characters that are valid for custom keys.
	customKeyCharset = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_"
	// errServerError contains the generic error message users will se when somthing goes wrong
	errServerError      = "Internal Server Error"
	errInvalidKey       = "Invalid key"
	errInvalidKeyUsed   = "Invalid key, key is already in use"
	errInvalidCustomKey = "Invalid Custom Key was provided, valid characters are:\n" + customKeyCharset
	errNotImplemented   = "Not Implemented"
	errLowRAM           = "No Space available, new space will be available as old links become invalid"
)
