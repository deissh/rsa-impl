package rsa_impl

import (
	"os"
	"reflect"
	"rsa-impl/private_key"
	"rsa-impl/public_key"
	"testing"
)

const TestMessage = "lorem ipsu"

func TestEncryptPKCS1v15(t *testing.T) {
	rawPublicKey, _ := os.ReadFile("./test_data/public.pem")
	rawPrivateKey, _ := os.ReadFile("./test_data/private.pem")

	pk, err := public_key.FromPEM(rawPublicKey)
	if err != nil {
		t.Error(err)
	}

	privKey, err := private_key.FromPEM(rawPrivateKey)
	if err != nil {
		t.Error(err)
	}

	enc, err := EncryptPKCS1v15(pk, []byte(TestMessage))
	if err != nil {
		return
	}

	data, err := DecryptPKCS1v15(privKey, enc)
	if err != nil {
		return
	}

	if !reflect.DeepEqual(enc, data) {
		t.Errorf("encrypted %v\nmust be %v", data, enc)
	}
}
