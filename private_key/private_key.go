package private_key

import (
	"io"
	"math/big"
	"rsa-impl/public_key"
)

type PrivateKey struct {
	public_key.PublicKey
	D *big.Int
}

// Public returns the public key
func (p *PrivateKey) Public() *public_key.PublicKey {
	return &p.PublicKey
}

func (p *PrivateKey) Decrypt(rand io.Reader, ciphertext []byte) (plaintext []byte, err error) {
	return nil, nil
}
