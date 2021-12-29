package rsa_impl

import (
	"os"
	"reflect"
	"rsa-impl/private_key"
	"rsa-impl/public_key"
	"testing"
)

var TestMessage = []byte("lorem ipsu test message")

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

	enc, err := EncryptPKCS1v15(pk, TestMessage)
	if err != nil {
		t.Error(err)
	}

	data, err := DecryptPKCS1v15(privKey, enc)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(TestMessage, data) {
		t.Errorf("encrypted %v\nmust be %v", data, enc)
	}
}
