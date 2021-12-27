package public_key

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
)

type PublicKey struct {
	N *big.Int // modules
	E int // exponent
}

func FromPEM(raw []byte) (*PublicKey, error) {
	block, _ := pem.Decode(raw)
	pub, _ := x509.ParsePKIXPublicKey(block.Bytes)

	decoded, _ := pub.(*rsa.PublicKey)

	key := &PublicKey{decoded.N, decoded.E}
	if err := checkPub(key); err != nil {
		return nil, err
	}

	return key, nil
}

// Size returns the modulus size in bytes
func (pub *PublicKey) Size() int {
	return (pub.N.BitLen() + 7) / 8
}
