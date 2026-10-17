package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
)

func validClaimHash(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, c := range value {
		if !('0' <= c && c <= '9') && !('a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

func matchesClaimToken(token, expectedHash string) bool {
	if len(token) != base64.RawURLEncoding.EncodedLen(32) || !validClaimHash(expectedHash) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token {
		return false
	}
	digest := sha256.Sum256(decoded)
	expected, err := hex.DecodeString(expectedHash)
	return err == nil && subtle.ConstantTimeCompare(digest[:], expected) == 1
}
