package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

type HMAC struct{}

// Calculates the HMAC of params by the given key
func (h *HMAC) Sign(key []byte, params ...[]byte) []byte {
	hash := hmac.New(sha256.New, key)
	for _, param := range params {
		hash.Write(param)
	}
	return hash.Sum(nil)
}

// Compare Compares two hmac parameters
func (h *HMAC) Compare(mac1, mac2 []byte) bool {
	return hmac.Equal(mac1, mac2)
}
