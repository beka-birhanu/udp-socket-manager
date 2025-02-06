package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// RSA is an implementation of asymmetric cryptography using RSA.
type RSA struct {
	privKey *rsa.PrivateKey
}

// NewRSA returns a new instance of RSA initialized with a private key.
func NewRSA(pk *rsa.PrivateKey) *RSA {
	return &RSA{privKey: pk}
}

// Decrypt decrypts the provided ciphertext using RSA-OAEP with SHA-1.
func (rd *RSA) Decrypt(cipher []byte) ([]byte, error) {
	return rd.privKey.Decrypt(rand.Reader, cipher, &rsa.OAEPOptions{Hash: crypto.SHA1}) // SHA-1 used for compatibility
}

// Encrypt encrypts the provided plaintext using RSA-OAEP with SHA-1 and the given public key.
func (c *RSA) Encrypt(payload []byte, pubKeyBytes []byte) ([]byte, error) {
	// Decode the public key
	pubKey, err := pubKeyFromBytes(pubKeyBytes)
	if err != nil {
		return nil, err
	}

	// Encrypt the payload
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, pubKey, payload, nil)
}

// GetPublicKey returns the public key in PEM-encoded format.
func (c *RSA) GetPublicKey() []byte {
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&c.privKey.PublicKey)
	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	return pem.EncodeToMemory(block)
}

// pubKeyFromBytes decodes an RSA public key from PEM-encoded bytes.
func pubKeyFromBytes(pubKeyBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubKeyBytes)
	if block == nil {
		return nil, errors.New("invalid public key format")
	}

	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

