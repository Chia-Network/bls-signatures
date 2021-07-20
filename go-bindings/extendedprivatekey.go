package blschia

// #cgo LDFLAGS: -L../build -lbls -lstdc++
// #cgo CXXFLAGS: -std=c++14 -I../src -I../build/contrib/relic/include -I../contrib/relic/include
// #include <stdbool.h>
// #include <stdlib.h>
// #include "extendedprivatekey.h"
// #include "extendedpublickey.h"
// #include "publickey.h"
// #include "blschia.h"
import "C"
import "runtime"

// ExtendedPrivateKey represents a BIP-32 style extended key, which is composed
// of a private key and a chain code.
type ExtendedPrivateKey struct {
	key C.CExtendedPrivateKey
}

// ExtendedPrivateKeyFromSeed generates a master private key and chain code
// from a seed
func ExtendedPrivateKeyFromSeed(seed []byte) ExtendedPrivateKey {
	// Get a C pointer to bytes
	cBytesPtr := C.CBytes(seed)
	defer C.free(cBytesPtr)

	var key ExtendedPrivateKey
	key.key = C.CExtendedPrivateKeyFromSeed(cBytesPtr, C.size_t(len(seed)))
	runtime.SetFinalizer(&key, func(p *ExtendedPrivateKey) { p.Free() })

	return key
}

// ExtendedPrivateKeyFromBytes parses a private key and chain code from bytes
func ExtendedPrivateKeyFromBytes(data []byte) ExtendedPrivateKey {
	// Get a C pointer to bytes
	cBytesPtr := C.CBytes(data)
	defer C.free(cBytesPtr)

	var key ExtendedPrivateKey
	key.key = C.CExtendedPrivateKeyFromBytes(cBytesPtr)
	runtime.SetFinalizer(&key, func(p *ExtendedPrivateKey) { p.Free() })

	return key
}

// Free releases memory allocated by the key
func (key ExtendedPrivateKey) Free() {
	C.CExtendedPrivateKeyFree(key.key)
}

// Serialize returns the serialized byte representation of the
// ExtendedPrivateKey object
func (key ExtendedPrivateKey) Serialize() []byte {
	ptr := C.CExtendedPrivateKeySerialize(key.key)
	defer C.SecFree(ptr)
	return C.GoBytes(ptr, C.CExtendedPrivateKeySizeBytes())
}

// GetPublicKey returns the PublicKey which corresponds to the PrivateKey for
// the given node
func (key ExtendedPrivateKey) GetPublicKey() PublicKey {
	var pk PublicKey
	pk.pk = C.CExtendedPrivateKeyGetPublicKey(key.key)
	runtime.SetFinalizer(&pk, func(p *PublicKey) { p.Free() })
	return pk
}

// GetChainCode returns the ChainCode for the given node
func (key ExtendedPrivateKey) GetChainCode() ChainCode {
	var cc ChainCode
	cc.cc = C.CExtendedPrivateKeyGetChainCode(key.key)
	runtime.SetFinalizer(&cc, func(p *ChainCode) { p.Free() })
	return cc
}

// PrivateChild derives a child ExtendedPrivateKey
func (key ExtendedPrivateKey) PrivateChild(i uint32) ExtendedPrivateKey {
	if key.GetDepth() >= 255 {
		panic("cannot go further than 255 levels")
	}
	var child ExtendedPrivateKey
	child.key = C.CExtendedPrivateKeyPrivateChild(key.key, C.uint(i))
	runtime.SetFinalizer(&child, func(p *ExtendedPrivateKey) { p.Free() })
	return child
}

// GetExtendedPublicKey returns the extended public key which corresponds to
// the extended private key for the given node
func (key ExtendedPrivateKey) GetExtendedPublicKey() ExtendedPublicKey {
	var xpub ExtendedPublicKey
	xpub.key = C.CExtendedPrivateKeyGetExtendedPublicKey(key.key)
	runtime.SetFinalizer(&xpub, func(p *ExtendedPublicKey) { p.Free() })
	return xpub
}

// GetVersion returns the version bytes
func (key ExtendedPrivateKey) GetVersion() uint32 {
	return uint32(C.CExtendedPrivateKeyGetVersion(key.key))
}

// GetDepth returns the depth byte
func (key ExtendedPrivateKey) GetDepth() uint8 {
	return uint8(C.CExtendedPrivateKeyGetDepth(key.key))
}

// GetParentFingerprint returns the parent fingerprint
func (key ExtendedPrivateKey) GetParentFingerprint() uint32 {
	return uint32(C.CExtendedPrivateKeyGetParentFingerprint(key.key))
}

// GetChildNumber returns the child number
func (key ExtendedPrivateKey) GetChildNumber() uint32 {
	return uint32(C.CExtendedPrivateKeyGetChildNumber(key.key))
}

// GetPrivateKey returns the private key at the given node
func (key ExtendedPrivateKey) GetPrivateKey() PrivateKey {
	var sk PrivateKey
	sk.sk = C.CExtendedPrivateKeyGetPrivateKey(key.key)
	runtime.SetFinalizer(&sk, func(p *PrivateKey) { p.Free() })
	return sk
}

// Equal tests if one ExtendedPrivateKey object is equal to another
//
// Only the privatekey and chaincode material is tested
func (key ExtendedPrivateKey) Equal(other ExtendedPrivateKey) bool {
	return bool(C.CExtendedPrivateKeyIsEqual(key.key, other.key))
}
