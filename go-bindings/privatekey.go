package blschia

// #cgo LDFLAGS: -L../build -lbls -lstdc++
// #cgo CXXFLAGS: -std=c++14 -I../src -I../build/contrib/relic/include -I../contrib/relic/include
// #include <stdbool.h>
// #include <stdlib.h>
// #include "privatekey.h"
// #include "blschia.h"
import "C"
import (
	"errors"
	"math/big"
	"runtime"
	"unsafe"
)

// PrivateKey represents a BLS private key
type PrivateKey struct {
	sk C.CPrivateKey
}

// PrivateKeyFromSeed generates a private key from a seed, similar to HD key
// generation (hashes the seed), and reduces it mod the group order
func PrivateKeyFromSeed(seed []byte) PrivateKey {
	// Get a C pointer to bytes
	cBytesPtr := C.CBytes(seed)
	defer C.free(cBytesPtr)

	var sk PrivateKey
	sk.sk = C.CPrivateKeyFromSeed(cBytesPtr, C.int(len(seed)))
	runtime.SetFinalizer(&sk, func(p *PrivateKey) { p.Free() })
	return sk
}

// PrivateKeyFromBytes constructs a new private key from bytes
func PrivateKeyFromBytes(data []byte, modOrder bool) (PrivateKey, error) {
	// Get a C pointer to bytes
	cBytesPtr := C.CBytes(data)
	defer C.free(cBytesPtr)

	var sk PrivateKey
	var cDidErr C.bool
	sk.sk = C.CPrivateKeyFromBytes(cBytesPtr, C.bool(modOrder), &cDidErr)
	if bool(cDidErr) {
		cErrMsg := C.GetLastErrorMsg()
		err := errors.New(C.GoString(cErrMsg))
		return PrivateKey{}, err
	}

	runtime.SetFinalizer(&sk, func(p *PrivateKey) { p.Free() })
	return sk, nil
}

// Free releases memory allocated by the key
func (sk PrivateKey) Free() {
	C.CPrivateKeyFree(sk.sk)
}

// Serialize returns the byte representation of the private key
func (sk PrivateKey) Serialize() []byte {
	ptr := C.CPrivateKeySerialize(sk.sk)
	defer C.SecFree(ptr)
	return C.GoBytes(ptr, C.CPrivateKeySizeBytes())
}

// PublicKey returns the public key which corresponds to the private key
func (sk PrivateKey) PublicKey() PublicKey {
	var pk PublicKey
	pk.pk = C.CPrivateKeyGetPublicKey(sk.sk)
	runtime.SetFinalizer(&pk, func(p *PublicKey) { p.Free() })
	return pk
}

// SignInsecure signs a message without setting aggreagation info
func (sk PrivateKey) SignInsecure(message []byte) InsecureSignature {
	// Get a C pointer to bytes
	cMessagePtr := C.CBytes(message)
	defer C.free(cMessagePtr)

	var sig InsecureSignature
	sig.sig = C.CPrivateKeySignInsecure(sk.sk, cMessagePtr, C.size_t(len(message)))
	runtime.SetFinalizer(&sig, func(p *InsecureSignature) { p.Free() })
	return sig
}

// Sign securely signs a message, and sets and returns appropriate aggregation
// info
func (sk PrivateKey) Sign(message []byte) Signature {
	// Get a C pointer to bytes
	cMessagePtr := C.CBytes(message)
	defer C.free(cMessagePtr)

	var sig Signature
	sig.sig = C.CPrivateKeySign(sk.sk, cMessagePtr, C.size_t(len(message)))
	runtime.SetFinalizer(&sig, func(p *Signature) { p.Free() })
	return sig
}

// PrivateKeyAggregateInsecure insecurely aggregates multiple private keys into
// one.
func PrivateKeyAggregateInsecure(privateKeys []PrivateKey) (PrivateKey, error) {
	// Get a C pointer to an array of private keys
	cPrivKeyArrPtr := C.AllocPtrArray(C.size_t(len(privateKeys)))
	defer C.FreePtrArray(cPrivKeyArrPtr)
	// Loop thru each key and add the key C ptr to the array of ptrs at index
	for i, privKey := range privateKeys {
		C.SetPtrArray(cPrivKeyArrPtr, unsafe.Pointer(privKey.sk), C.int(i))
	}

	var sk PrivateKey
	var cDidErr C.bool
	sk.sk = C.CPrivateKeyAggregateInsecure(cPrivKeyArrPtr, C.size_t(len(privateKeys)), &cDidErr)
	if bool(cDidErr) {
		cErrMsg := C.GetLastErrorMsg()
		err := errors.New(C.GoString(cErrMsg))
		return PrivateKey{}, err
	}

	runtime.SetFinalizer(&sk, func(p *PrivateKey) { p.Free() })
	return sk, nil
}

// PrivateKeyAggregate securely aggregates multiple private keys into one by
// exponentiating the keys with the pubKey hashes first
func PrivateKeyAggregate(privateKeys []PrivateKey, publicKeys []PublicKey) (PrivateKey, error) {
	// Get a C pointer to an array of private keys
	cPrivKeyArrPtr := C.AllocPtrArray(C.size_t(len(privateKeys)))
	defer C.FreePtrArray(cPrivKeyArrPtr)
	// Loop thru each key and add the key C ptr to the array of ptrs at index
	for i, privKey := range privateKeys {
		C.SetPtrArray(cPrivKeyArrPtr, unsafe.Pointer(privKey.sk), C.int(i))
	}

	// Get a C pointer to an array of public keys
	cPubKeyArrPtr := C.AllocPtrArray(C.size_t(len(publicKeys)))
	defer C.FreePtrArray(cPubKeyArrPtr)
	// Loop thru each key and add the key C ptr to the array of ptrs at index
	for i, pubKey := range publicKeys {
		C.SetPtrArray(cPubKeyArrPtr, unsafe.Pointer(pubKey.pk), C.int(i))
	}

	var cDidErr C.bool
	var sk PrivateKey
	sk.sk = C.CPrivateKeyAggregate(cPrivKeyArrPtr, C.size_t(len(privateKeys)),
		cPubKeyArrPtr, C.size_t(len(publicKeys)), &cDidErr)
	if bool(cDidErr) {
		cErrMsg := C.GetLastErrorMsg()
		err := errors.New(C.GoString(cErrMsg))
		return PrivateKey{}, err
	}

	runtime.SetFinalizer(&sk, func(p *PrivateKey) { p.Free() })
	return sk, nil
}

// Equal tests if one PrivateKey object is equal to another
func (sk PrivateKey) Equal(other PrivateKey) bool {
	return bool(C.CPrivateKeyIsEqual(sk.sk, other.sk))
}

// PrivateKeyFromBN constructs a new private key from a *big.Int
func PrivateKeyFromBN(bn *big.Int) PrivateKey {
	// Get a C pointer to bytes
	bnBytes := bn.Bytes()
	cBNBytesPtr := C.CBytes(bnBytes)
	defer C.free(cBNBytesPtr)

	var sk PrivateKey
	sk.sk = C.CPrivateKeyFromBN(cBNBytesPtr, C.size_t(len(bnBytes)))
	runtime.SetFinalizer(&sk, func(p *PrivateKey) { p.Free() })
	return sk
}
