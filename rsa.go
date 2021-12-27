package rsa_impl

import (
	"math/big"
	"rsa-impl/private_key"
	"rsa-impl/public_key"
)

func encrypt(pub *public_key.PublicKey, m *big.Int) *big.Int {
	c := new(big.Int)
	e := big.NewInt(int64(pub.E))

	c.Exp(m, e, pub.N)
	return c
}

func decrypt(privateKey *private_key.PrivateKey, c *big.Int) *big.Int {
	m := new(big.Int)

	m.Exp(c, privateKey.D, privateKey.N)
	return m
}
