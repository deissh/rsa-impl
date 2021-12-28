package private_key

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"rsa-impl/public_key"
)

type PrivateKey struct {
	public_key.PublicKey
	D *big.Int

	Version int
}

func FromPEM(raw []byte) (*PrivateKey, error) {
	block, _ := pem.Decode(raw)

	dat, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	key := dat.(*rsa.PrivateKey)
	return &PrivateKey{
		PublicKey: public_key.PublicKey{
			N: key.N,
			E: key.E,
		},
		D:       key.D,
		Version: 0,
	}, nil
}

// Public returns the public key
func (p *PrivateKey) Public() *public_key.PublicKey {
	return &p.PublicKey
}
