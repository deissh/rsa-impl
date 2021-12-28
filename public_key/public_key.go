package public_key

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"golang.org/x/crypto/cryptobyte"
	asn1_cb "golang.org/x/crypto/cryptobyte/asn1"
	"math/big"
)

type PublicKey struct {
	N *big.Int // modules
	E int      // exponent
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func FromPEM(raw []byte) (*PublicKey, error) {
	block, _ := pem.Decode(raw)

	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(block.Bytes, &pki); err != nil {
		if _, err := asn1.Unmarshal(block.Bytes, &PublicKey{}); err == nil {
			return nil, errors.New("x509: failed to parse public key (use ParsePKCS1PublicKey instead for this key format)")
		}
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}

	switch getPublicKeyAlgorithmFromOID(pki.Algorithm.Algorithm) {
	case RSA:
		der := cryptobyte.String(pki.PublicKey.RightAlign())

		// RSA public keys must have a NULL in the parameters.
		// See RFC 3279, Section 2.3.1.
		if !bytes.Equal(pki.Algorithm.Parameters.FullBytes, asn1.NullBytes) {
			return nil, errors.New("x509: RSA key missing NULL parameters")
		}

		p := &PublicKey{N: new(big.Int)}
		if !der.ReadASN1(&der, asn1_cb.SEQUENCE) {
			return nil, errors.New("x509: invalid RSA public key")
		}
		if !der.ReadASN1Integer(p.N) {
			return nil, errors.New("x509: invalid RSA modulus")
		}
		if !der.ReadASN1Integer(&p.E) {
			return nil, errors.New("x509: invalid RSA public exponent")
		}

		if p.N.Sign() <= 0 {
			return nil, errors.New("x509: RSA modulus is not a positive number")
		}
		if p.E <= 0 {
			return nil, errors.New("x509: RSA public exponent is not a positive number")
		}

		pub := &PublicKey{
			E: p.E,
			N: p.N,
		}

		if err := checkPub(pub); err != nil {
			return nil, err
		}
		return pub, nil
	default:
		return nil, errors.New("x509: key unsupported alg")
	}
}

// Size returns the modulus size in bytes
func (pub *PublicKey) Size() int {
	return (pub.N.BitLen() + 7) / 8
}
