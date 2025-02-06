package crypto

import (
	"bytes"
	"testing"
)

var (
	plaintext  = []byte("test")
	aesKey     = []byte{113, 110, 25, 53, 11, 53, 68, 33, 17, 36, 22, 7, 125, 11, 35, 16, 83, 61, 59, 49, 31, 22, 69, 17, 24, 125, 11, 35, 16, 83, 61, 59}
	invalidKey = []byte("shortkey")
)

// TestAESCBC contains all the tests related to RSA encryption and decryption.
func TestAESCBC(t *testing.T) {
	t.Run("AESCBC_Encrypt", testAESCBC_Encrypt)
	t.Run("AESCBC_InvalidKeyLength", testAESCBC_InvalidKeyLength)
	t.Run("AESCBC_DecryptWithWrongKey", testAESCBC_DecryptWithWrongKey)
	t.Run("AESCBC_EmptyPlaintext", testAESCBC_EmptyPlaintext)
	t.Run("AESCBC_LargePlaintext", testAESCBC_LargePlaintext)
}

// testAESCBC_Encrypt tests the encryption and decryption of AES in CBC mode.
func testAESCBC_Encrypt(t *testing.T) {
	aes := NewAESCBC()
	c, err := aes.Encrypt(plaintext, aesKey)
	if err != nil {
		t.Errorf("Expected cipher, got error: %s", err)
		t.FailNow()
	}

	if bytes.Equal(c, plaintext) {
		t.Errorf("Cipher is the same as plain text")
		t.FailNow()
	}

	d, err := aes.Decrypt(c, aesKey)
	if err != nil {
		t.Errorf("Expected decrypted text, got error: %s", err)
		t.FailNow()
	}

	if !bytes.Equal(d, plaintext) {
		t.Errorf("Expected decrypted text: %s, got wrong value: %s", plaintext, d)
		t.FailNow()
	}
}

// testAESCBC_InvalidKeyLength tests encryption with an invalid AES key length.
func testAESCBC_InvalidKeyLength(t *testing.T) {
	aes := NewAESCBC()

	// Try encrypting with an invalid key length (too short)
	c, err := aes.Encrypt(plaintext, invalidKey)
	if err == nil {
		t.Errorf("Expected error with invalid key length, got cipher: %x", c)
	}
}

// testAESCBC_DecryptWithWrongKey tests decryption with the wrong key.
func testAESCBC_DecryptWithWrongKey(t *testing.T) {
	aes := NewAESCBC()

	// Encrypt with the correct key
	c, err := aes.Encrypt(plaintext, aesKey)
	if err != nil {
		t.Errorf("Expected cipher, got error: %s", err)
		t.FailNow()
	}

	// Use a different key to decrypt
	differentKey := []byte("wrongkey12345678") // Some other key
	d, err := aes.Decrypt(c, differentKey)
	if err == nil {
		t.Errorf("Expected error with wrong key, got decrypted text: %s", d)
	}
}

// testAESCBC_EmptyPlaintext tests encryption and decryption with empty plaintext.
func testAESCBC_EmptyPlaintext(t *testing.T) {
	aes := NewAESCBC()

	// Encrypt empty plaintext
	emptyPlaintext := []byte{}
	c, err := aes.Encrypt(emptyPlaintext, aesKey)
	if err != nil {
		t.Errorf("Expected cipher, got error: %s", err)
		t.FailNow()
	}

	// Decrypt the empty ciphertext
	d, err := aes.Decrypt(c, aesKey)
	if err != nil {
		t.Errorf("Expected decrypted text, got error: %s", err)
		t.FailNow()
	}

	if !bytes.Equal(d, emptyPlaintext) {
		t.Errorf("Expected decrypted empty text, got wrong value: %s", d)
	}
}

// testAESCBC_LargePlaintext tests encryption and decryption with large plaintext.
func testAESCBC_LargePlaintext(t *testing.T) {
	aes := NewAESCBC()

	// Generate a large plaintext (multiple blocks)
	largePlaintext := []byte("A large amount of text that will span multiple blocks. " +
		"This ensures that padding and block-level operations are properly handled by AES.")

	// Encrypt the large plaintext
	c, err := aes.Encrypt(largePlaintext, aesKey)
	if err != nil {
		t.Errorf("Expected cipher, got error: %s", err)
		t.FailNow()
	}

	// Decrypt the ciphertext
	d, err := aes.Decrypt(c, aesKey)
	if err != nil {
		t.Errorf("Expected decrypted text, got error: %s", err)
		t.FailNow()
	}

	// Check if decrypted text matches the original plaintext
	if !bytes.Equal(d, largePlaintext) {
		t.Errorf("Expected decrypted text: %s, got wrong value: %s", largePlaintext, d)
	}
}
