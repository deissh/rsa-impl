package public_key

import (
	"errors"
)

var (
	errPublicModulus = errors.New("invalid modules in public key")
	errPublicExponentSmall = errors.New("exponent too small")
	errPublicExponentLarge = errors.New("exponent too large")
)

func checkPub(pub *PublicKey) error {
	if pub.N == nil {
		return errPublicModulus
	}
	if pub.E < 2 {
		return errPublicExponentSmall
	}
	if pub.E > 1<<31-1 {
		return errPublicExponentLarge
	}
	return nil
}

