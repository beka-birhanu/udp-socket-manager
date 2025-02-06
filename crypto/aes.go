// An implementation of symmetric cryptography with AES and CBC
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// errors
var (
	ErrInvalidAESMode              = errors.New("invalid AES encryption mode")
	ErrCipherTextTooShortToDecrypt = errors.New("ciphertext is too short to decrypt")
	ErrCipherTextIsEmpty           = errors.New("ciphertext is empty")
	ErrCipherTextIsNotBlockAligned = errors.New("ciphertext is not block-aligned")
	ErrCipherTextIncorrectlyPadded = errors.New("ciphertext is not padded according to PKCS#7")
)

// AESCBC implements AES CBC symmetric cryptography
type AESCBC struct{}

// NewAESCBC returns a new instance of AESCBC implementation
func NewAESCBC() *AESCBC {
	return &AESCBC{}
}

// Decrypt implements Symmetric.
func (a *AESCBC) Decrypt(c []byte, k []byte) ([]byte, error) {
	return a.cbcDecrypt(c, k)
}

// Encrypt implements Symmetric.
func (a *AESCBC) Encrypt(p []byte, k []byte) ([]byte, error) {
	return a.cbcEncrypt(p, k)
}

// pkcs7Padding adds padding to the plaintext using PKCS#7
func pkcs7Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	return append(plaintext, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

// cbcEncrypt encrypts a byte array using the given key with CBC mode and PKCS#7 padding
func (a *AESCBC) cbcEncrypt(plainBytes, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil { // Invalid key size
		return nil, err
	}

	blockSize := block.BlockSize()
	plainBytes = pkcs7Padding(plainBytes, blockSize)
	cipherBytes := make([]byte, blockSize+len(plainBytes))

	iv := cipherBytes[:blockSize] // Initialization vector
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	encrypter := cipher.NewCBCEncrypter(block, iv)
	encrypter.CryptBlocks(cipherBytes[blockSize:], plainBytes)
	return cipherBytes, nil
}

// cbcDecrypt decrypts a byte array using the given key with CBC mode and removes PKCS#7 padding
func (a *AESCBC) cbcDecrypt(cipherBytes, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(cipherBytes) < aes.BlockSize {
		return nil, ErrCipherTextTooShortToDecrypt
	}

	iv := cipherBytes[:aes.BlockSize] // Initialization vector used
	cipherBytes = cipherBytes[aes.BlockSize:]
	decipherBytes := make([]byte, len(cipherBytes))

	decrypter := cipher.NewCBCDecrypter(block, iv)
	decrypter.CryptBlocks(decipherBytes, cipherBytes)

	decipherBytes, err = pkcs7UnPadding(decipherBytes, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return decipherBytes, nil
}

// pkcs7UnPadding removes padding from the plaintext using PKCS#7
func pkcs7UnPadding(ciphertext []byte, blockSize int) ([]byte, error) {
	length := len(ciphertext)
	if length == 0 {
		return nil, ErrCipherTextIsEmpty
	}
	if length%blockSize != 0 {
		return nil, ErrCipherTextIsNotBlockAligned
	}
	padLen := int(ciphertext[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(ciphertext, ref) {
		return nil, ErrCipherTextIncorrectlyPadded
	}
	return ciphertext[:length-padLen], nil
}

