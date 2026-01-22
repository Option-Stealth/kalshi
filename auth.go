package kalshi

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

var (
	ErrInvalidPEMBlock = errors.New("failed to parse PEM block")
	ErrEncryptedKey    = errors.New("private key is encrypted but no password provided")
	ErrKeyDecryption   = errors.New("failed to decrypt private key")
)

// LoadPrivateKeyFromPEM loads an RSA private key from PEM-encoded data.
// If the key is encrypted, a password must be provided.
func LoadPrivateKeyFromPEM(pemData []byte, password string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, ErrInvalidPEMBlock
	}

	if x509.IsEncryptedPEMBlock(block) {
		if password == "" {
			return nil, ErrEncryptedKey
		}
		decrypted, err := x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKeyDecryption, err)
		}
		return x509.ParsePKCS1PrivateKey(decrypted)
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
