package rsa_impl

import (
	"os"
	"reflect"
	"rsa-impl/public_key"
	"testing"
)

func TestEncryptPKCS1v15(t *testing.T) {
	rawKey, _ := os.ReadFile("./test_data/public.pem")

	testFile, _ := os.ReadFile("./test_data/file.txt")
	enc, _ := os.ReadFile("./test_data/file.txt.enc")

	pk, err := public_key.FromPEM(rawKey)
	if err != nil {
		t.Error(err)
	}

	data, err := EncryptPKCS1v15(pk, testFile)
	if err != nil {
		return
	}

	if !reflect.DeepEqual(enc, data) {
		t.Errorf("encrypted %v\nmust be %v", data, enc)
	}
}
