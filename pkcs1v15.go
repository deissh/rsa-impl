package rsa_impl

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"rsa-impl/private_key"
	"rsa-impl/public_key"
)

// EncryptPKCS1v15 ...
func EncryptPKCS1v15(publicKey *public_key.PublicKey, m []byte) ([]byte, error) {
	keyLen := (publicKey.N.BitLen() + 7) / 8
	if len(m) > keyLen-11 {
		return nil, errors.New("encryption data too long")
	}

	// PKCS1v15
	// EB = 00 || 02 || PS || 00 || D
	psLen := keyLen - len(m) - 3
	eb := make([]byte, keyLen)
	eb[0] = 0x00
	eb[1] = 0x02

	for i := 2; i < 2+psLen; {
		_, err := rand.Read(eb[i : i+1])
		if err != nil {
			return nil, err
		}
		if eb[i] != 0x00 {
			i++
		}
	}
	eb[2+psLen] = 0x00

	copy(eb[3+psLen:], m)

	mnum := new(big.Int).SetBytes(eb)
	c := encrypt(publicKey, mnum)

	padLen := keyLen - len(c.Bytes())
	for i := 0; i < padLen; i++ {
		eb[i] = 0x00
	}
	copy(eb[padLen:], c.Bytes())
	return eb, nil
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