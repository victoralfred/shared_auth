package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// SignRSA signs data using RSA private key
func SignRSA(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// VerifyRSA verifies RSA signature
func VerifyRSA(data []byte, signature []byte, publicKey *rsa.PublicKey) error {
	hash := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature)
}
