package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestRSA(t *testing.T) {
	t.Run("EncryptDecrypt", testRSA_EncryptDecrypt)
	t.Run("EncryptWithDifferentPublicKey", testRSA_EncryptWithDifferentPublicKey)
}

// testRSA_EncryptDecrypt tests encryption and decryption using RSA.
func testRSA_EncryptDecrypt(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	rsaCrypto := NewRSA(privKey)

	plaintext := []byte("Hello, RSA!")

	pubKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privKey.PublicKey),
	})

	ciphertext, err := rsaCrypto.Encrypt(plaintext, pubKeyBytes)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if string(ciphertext) == string(plaintext) {
		t.Errorf("Encryption failed: ciphertext %s is the same as plaintext %s", ciphertext, plaintext)
	}

	decrypted, err := rsaCrypto.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decryption mismatch: got %s, want %s", decrypted, plaintext)
	}
}

// testRSA_EncryptWithDifferentPublicKey tests RSA encryption and decryption with different public and private keys.
func testRSA_EncryptWithDifferentPublicKey(t *testing.T) {
	encryptPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate encryption private key: %v", err)
	}

	decryptPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate decryption private key: %v", err)
	}

	rsaCrypto := NewRSA(decryptPrivKey)

	plaintext := []byte("Hello, RSA!")

	encryptPubKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&encryptPrivKey.PublicKey),
	})

	// Encrypt the plaintext using a different public key
	ciphertext, err := rsaCrypto.Encrypt(plaintext, encryptPubKeyBytes)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Attempt decryption with the private key of the RSA instance (should fail)
	_, err = rsaCrypto.Decrypt(ciphertext)
	if err == nil {
		t.Errorf("Expected decryption to fail with mismatched key, but it succeeded")
	}
}

