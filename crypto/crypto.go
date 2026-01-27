package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

type KeyPair struct {
	PublicKey  string `json:"public_key"`  // base64url encoded (32 bytes)
	PrivateKey string `json:"private_key"` // base64url encoded (64 bytes)
}

// CreateNewKeyPair generates a new Ed25519 keypair.
//
// The returned keys are base64url-encoded (no padding),
// safe for JSON storage and transport.
func CreateNewKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 keypair: %w", err)
	}

	return &KeyPair{
		PublicKey:  base64.RawURLEncoding.EncodeToString(pub),
		PrivateKey: base64.RawURLEncoding.EncodeToString(priv),
	}, nil
}

func DecodePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: %d", len(b))
	}
	return ed25519.PrivateKey(b), nil
}

func (kp *KeyPair) DecodePrivateKey() (ed25519.PrivateKey, error) {
	if kp == nil {
		return nil, fmt.Errorf("key pair is nil")
	}
	return DecodePrivateKey(kp.PrivateKey)
}

func DecodePublicKey(encoded string) (ed25519.PublicKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: %d", len(b))
	}
	return ed25519.PublicKey(b), nil
}
