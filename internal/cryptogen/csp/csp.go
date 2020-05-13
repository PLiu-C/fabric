/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package csp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sm/sm2"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/pkg/errors"
)

// LoadPrivateKey loads a private key from a file in keystorePath.  It looks
// for a file ending in "_sk" and expects a PEM-encoded PKCS8 EC private key.
func LoadPrivateKey(keystorePath string) (interface{}, error) {
	var priv interface{} // PLIU: *ecdsa.PrivateKey

	walkFunc := func(path string, info os.FileInfo, pathErr error) error {

		if !strings.HasSuffix(path, "_sk") {
			return nil
		}

		rawKey, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		priv, err = parsePrivateKeyPEM(rawKey)
		if err != nil {
			return errors.WithMessage(err, path)
		}

		return nil
	}

	err := filepath.Walk(keystorePath, walkFunc)
	if err != nil {
		return nil, err
	}

	return priv, err
}

func parsePrivateKeyPEM(rawKey []byte) (interface{}, error) {
	block, _ := pem.Decode(rawKey)
	if block == nil {
		return nil, errors.New("bytes are not PEM encoded")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.WithMessage(err, "pem bytes are not PKCS8 encoded ")
	}

	switch key(.type) {
	case *ecdsa.PrivateKey, *sm2.PrivateKey:
		return key, nil
	default:
		return nil, errors.New("pem bytes do not contain an EC or SM private key")
	}
}

// GeneratePrivateKey creates an EC private key using a P-256 curve and stores
// it in keystorePath.
// PLIU: depending on sigAlso (sm2 or ecdsa), interface returned could be type
// of *sm2.PrivateKey or *ecdsa.PrivateKey.
func GeneratePrivateKey(keystorePath string, sigAlgo string) (interface{}, error) {
	var err error
	var priv interface{}

	switch sigAlgo {
	case "ecdsa":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "sm2":
		priv, err = sm2.GenerateKey()
	default:
		err = errors.Errorf("Unrecognized sigAlgo: %s", sigAlgo)
	}
	if err != nil {
		return nil, errors.WithMessage(err, "failed to generate private key")
	}

	pkcs8Encoded, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to marshal private key")
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Encoded})

	keyFile := filepath.Join(keystorePath, "priv_sk")
	err = ioutil.WriteFile(keyFile, pemEncoded, 0600)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to save private key to file %s", keyFile)
	}

	return priv, err
}

/**
ECDSA signer implements the crypto.Signer interface for ECDSA keys.  The
Sign method ensures signatures are created with Low S values since Fabric
normalizes all signatures to Low S.
See https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki#low_s
for more detail.
*/
type ECDSASigner struct {
	PrivateKey interface{}
	//PrivateKey *ecdsa.PrivateKey
}

func GetPublicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case *sm2.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

// Public returns the ecdsa.PublicKey associated with PrivateKey.
func (e *ECDSASigner) Public() crypto.PublicKey { // crypto.PublicKey is kinda interface{}
	switch k := e.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		return &k.PublicKey // *ecdsa.PublicKey
	case *sm2.PrivateKey:
		return &k.PublicKey // *sm2.PublicKey
	default:
		panic("ECDSASigner.Public: invalid private key")
	}
}

// Sign signs the digest and ensures that signatures use the Low S value.
func (e *ECDSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var r, s *big.Int
	var err error

	switch k := e.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		r, s, err = ecdsa.Sign(rand, k, digest)
	case *sm2.PrivateKey:
		r, s, err = sm2.Sm2Sign(k, digest, nil) // PLIU: nil is for UID which is 1234567812345678 by default
	default:
	}

	if err != nil {
		return nil, err
	}

	// ensure Low S signatures
	sig := toLowS(
		e.Public(),
		ECDSASignature{
			R: r,
			S: s,
		},
	)

	// return marshaled aignature
	return asn1.Marshal(sig)
}

/**
When using ECDSA, both (r,s) and (r, -s mod n) are valid signatures.  In order
to protect against signature malleability attacks, Fabric normalizes all
signatures to a canonical form where s is at most half the order of the curve.
In order to make signatures compliant with what Fabric expects, toLowS creates
signatures in this canonical form.
*/
func toLowS(key crypto.PublicKey, sig ECDSASignature) ECDSASignature {
	var k *ecdsa.PublicKey
	switch kk := key.(type) {
	case *ecdsa.PublicKey:
		k = kk
	case *sm2.PublicKey:
		k = (*ecdsa.PublicKey)(unsafe.Pointer(kk))
	default:
		panic(fmt.Sprintf("toLowS: invalid public key %v", kk))
	}

	// calculate half order of the curve
	halfOrder := new(big.Int).Div(k.Curve.Params().N, big.NewInt(2))
	// check if s is greater than half order of curve
	if sig.S.Cmp(halfOrder) == 1 {
		// Set s to N - s so that s will be less than or equal to half order
		sig.S.Sub(k.Params().N, sig.S)
	}
	return sig
}

type ECDSASignature struct {
	R, S *big.Int
}
