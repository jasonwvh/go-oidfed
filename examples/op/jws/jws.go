package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/zachmann/go-oidfed/examples/op/config"
	"log"
	"os"
	"path"

	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jwa"

	"github.com/zachmann/go-oidfed/pkg/jwk"
)

func mustNewKey() *ecdsa.PrivateKey {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return sk
}

func mustLoadKey(name string) crypto.Signer {
	data, err := os.ReadFile(path.Join(config.Conf.KeyStorage, name))
	if err != nil {
		sk := mustNewKey()
		if err = os.WriteFile(path.Join(config.Conf.KeyStorage, name), exportECPrivateKeyAsPem(sk), 0600); err != nil {
			log.Fatal(err)
		}
		return sk
	}
	sk, err := jwt.ParseECPrivateKeyFromPEM(data)
	if err != nil {
		log.Fatal(err)
	}
	return sk
}

var keys map[string]crypto.Signer
var jwks map[string]jwk.JWKS

func InitKeys(names ...string) {
	keys = make(map[string]crypto.Signer)
	jwks = make(map[string]jwk.JWKS)
	for _, name := range names {
		keys[name] = mustLoadKey(name)
		set := jwk.KeyToJWKS(keys[name].Public(), jwa.ES512)
		jwks[name] = set
	}
}

func GetKey(name string) crypto.Signer {
	return keys[name]
}
func GetJWKS(name string) *jwk.JWKS {
	set := jwks[name]
	return &set
}

func exportECPrivateKeyAsPem(privkey *ecdsa.PrivateKey) []byte {
	privkeyBytes, _ := x509.MarshalECPrivateKey(privkey)
	privkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privkeyBytes,
		},
	)
	return privkeyPem
}
