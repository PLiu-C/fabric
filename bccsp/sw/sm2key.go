package sw

import (
	"errors"

	"github.com/hyperledger/fabric/bccsp"

	sm "pliu/osslsm"
)

type sm2PrivateKey struct {
	key sm.Key
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *sm2PrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("Not supported")
}

// SKI returns the subject key identifier of this key.
func (k *sm2PrivateKey) SKI() []byte {
	res := make([]byte, 128)
	len := []int{cap(res)}
	k.key.Ski(res, len)
	return res[:len[0]]
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *sm2PrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *sm2PrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *sm2PrivateKey) PublicKey() (bccsp.Key, error) {
	return &sm2PublicKey{k.key.Pubkey()}, nil
}

type sm2PublicKey struct {
	key sm.Key
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *sm2PublicKey) Bytes() (raw []byte, err error) {
	res := make([]byte, 128)
	len := []int{cap(res)}
	k.key.Bytes(res, len)
	return res[:len[0]], nil
}

// SKI returns the subject key identifier of this key.
func (k *sm2PublicKey) SKI() []byte {
	res := make([]byte, 128)
	len := []int{cap(res)}
	k.key.Ski(res, len)
	return res[:len[0]]
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *sm2PublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *sm2PublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *sm2PublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}
