package rsa_impl

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"rsa-impl/private_key"
	"rsa-impl/public_key"
)

func nonZeroRandomBytes(s []byte, rand io.Reader) (err error) {
	_, err = io.ReadFull(rand, s)
	if err != nil {
		return
	}

	for i := 0; i < len(s); i++ {
		for s[i] == 0 {
			_, err = io.ReadFull(rand, s[i:i+1])
			if err != nil {
				return
			}
			// In tests, the PRNG may return all zeros so we do
			// this to break the loop.
			s[i] ^= 0x42
		}
	}

	return
}

// EncryptPKCS1v15 ...
func EncryptPKCS1v15(pub *public_key.PublicKey, msg []byte) ([]byte, error) {
	r := rand.Reader
	k := pub.Size()
	if len(msg) > k-11 {
		return nil, errors.New("err message too long")
	}

	// EM = 0x00 || 0x02 || PS || 0x00 || M
	em := make([]byte, k)
	em[1] = 2
	ps, mm := em[2:len(em)-len(msg)-1], em[len(em)-len(msg):]
	err := nonZeroRandomBytes(ps, r)
	if err != nil {
		return nil, err
	}
	em[len(em)-len(msg)-1] = 0
	copy(mm, msg)

	m := new(big.Int).SetBytes(em)
	c := encrypt(new(big.Int), pub, m)

	return c.FillBytes(em), nil
}

func DecryptPKCS1v15(privateKey *private_key.PrivateKey, c []byte) ([]byte, error) {
	keyLen := (privateKey.N.BitLen() + 7) / 8
	if len(c) != keyLen {
		return nil, errors.New("invalid key len")
	}

	cNum := new(big.Int).SetBytes(c)
	mNum := decrypt(privateKey, cNum)

	m := make([]byte, keyLen)
	copy(m[keyLen-len(mNum.Bytes()):], mNum.Bytes())

	if m[0] != 0x00 {
		return nil, errors.New("m[0] must eq 0x00")
	}
	if m[1] != 0x02 {
		return nil, errors.New("m[1] must eq 0x02")
	}

	// Skip over random padding until a 0x00 byte is reached. +2 adjusts the index
	// back to the full slice.
	endPad := bytes.IndexByte(m[2:], 0x00) + 2
	if endPad < 2 {
		return nil, fmt.Errorf("end of padding not found")
	}

	return m[endPad+1:], nil
}
