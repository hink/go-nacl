package secretbox

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

// SaltSize
const SaltSize = 16

// keySize
const KeySize = 32

// NonceSize
const NonceSize = 24

// KeyFromPassphrase generates a random salt and
// derives key material from passphrase
func KeyFromPassphrase(passphrase string) (*[KeySize]byte, *[SaltSize]byte, error) {
	// Check for empty secret
	if passphrase == "" {
		return nil, nil, errors.New("Empty passphrase")
	}

	// Generate Salt
	salt, err := GenerateSalt()
	if err != nil {
		return nil, nil, err
	}

	// Derive key
	key, err := deriveKey([]byte(passphrase), salt)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

// EncryptWithSecret Encrypt plaintext into ciphertext using supplied secret
func EncryptWithSecret(secret string, plaintext []byte) ([]byte, error) {
	errEncrypt := errors.New("Could not encrypt")

	// Derive key from passphrase
	key, salt, err := KeyFromPassphrase(secret)
	if err != nil {
		return nil, err
	}

	// Generate random Nonce
	nonce, err := generateNonce()
	if err != nil {
		return nil, errEncrypt
	}

	ciphertext, err := Encrypt(key, nonce, plaintext)
	if err != nil {
		return nil, errEncrypt
	}

	// Append Salt
	ciphertext = append(ciphertext, salt[:]...)

	return ciphertext, nil
}

// Encrypt returns ciphertext from plaintext
func Encrypt(key *[KeySize]byte, nonce *[NonceSize]byte, plaintext []byte) ([]byte, error) {
	ciphertext := make([]byte, len(nonce))
	copy(ciphertext, nonce[:])
	ciphertext = secretbox.Seal(ciphertext, plaintext, nonce, key)

	return ciphertext, nil
}

// Decrypt returns plaintext from ciphertext
func Decrypt(key *[KeySize]byte, nonce *[NonceSize]byte, ciphertext []byte) ([]byte, error) {
	plaintext, ok := secretbox.Open(nil, ciphertext, nonce, key)
	if !ok {
		return nil, errors.New("Could not decrypt")
	}
	return plaintext, nil
}

// DecryptWithSecret Decrypt ciphertext into plaintext using supplied secret
func DecryptWithSecret(secret string, ciphertext []byte) ([]byte, error) {
	errDecrypt := errors.New("Could not decrypt")

	// Check data to ensure enough data exists to decrypt
	if len(ciphertext) < (NonceSize + secretbox.Overhead) {
		return nil, errDecrypt
	}

	// Extract salt from ciphertext and derive key
	salt := new([SaltSize]byte)
	copy(salt[:], ciphertext[len(ciphertext)-SaltSize:])
	key, err := deriveKey([]byte(secret), salt)
	if err != nil {
		return nil, err
	}

	// Decrypt
	nonce := new([NonceSize]byte)
	copy(nonce[:], ciphertext[:NonceSize])
	ciphertext = ciphertext[NonceSize : len(ciphertext)-SaltSize]
	plaintext, err := Decrypt(key, nonce, ciphertext)
	if err != nil {
		return nil, errDecrypt
	}

	return plaintext, nil
}

// GenerateSalt generates a random salt
func GenerateSalt() (*[SaltSize]byte, error) {
	salt := new([SaltSize]byte)
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return salt, errors.New("Error creating salt")
	}
	return salt, nil
}

// Generates a random Nonce
func generateNonce() (*[NonceSize]byte, error) {
	nonce := new([NonceSize]byte)
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, errors.New("Error generating nonce")
	}

	return nonce, nil
}

// Derives key from a secret
func deriveKey(secret []byte, salt *[SaltSize]byte) (*[KeySize]byte, error) {
	dKey, err := scrypt.Key([]byte(secret), salt[:], 16384, 8, 1, KeySize)
	if err != nil {
		return nil, errors.New("Error deriving key")
	}
	key := new([32]byte)
	copy(key[:], dKey)
	return key, nil
}
