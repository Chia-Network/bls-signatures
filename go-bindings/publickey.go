package blschia

// #cgo LDFLAGS: -L../build -lbls -lstdc++
// #cgo CXXFLAGS: -std=c++14 -I../src -I../build/contrib/relic/include -I../contrib/relic/include
// #include <stdbool.h>
// #include <stdlib.h>
// #include "publickey.h"
// #include "blschia.h"
import "C"
import (
	"errors"
	"runtime"
	"unsafe"
)

// PublicKey represents a BLS public key
type PublicKey struct {
	pk C.CPublicKey
}

// PublicKeyFromBytes constructs a new public key from bytes
func PublicKeyFromBytes(data []byte) (PublicKey, error) {
	// Get a C pointer to bytes
	cBytesPtr := C.CBytes(data)
	defer C.free(cBytesPtr)

	var pk PublicKey
	var cDidErr C.bool
	pk.pk = C.CPublicKeyFromBytes(cBytesPtr, &cDidErr)
	if bool(cDidErr) {
		cErrMsg := C.GetLastErrorMsg()
		err := errors.New(C.GoString(cErrMsg))
		return PublicKey{}, err
	}

	runtime.SetFinalizer(&pk, func(p *PublicKey) { p.Free() })
	return pk, nil
}

// Free releases memory allocated by the key
func (pk PublicKey) Free() {
	C.CPublicKeyFree(pk.pk)
}

// Serialize returns the byte representation of the public key
func (pk PublicKey) Serialize() []byte {
	ptr := C.CPublicKeySerialize(pk.pk)
	defer C.free(ptr)
	return C.GoBytes(ptr, C.CPublicKeySizeBytes())
}

// Fingerprint returns the first 4 bytes of the serialized key
func (pk PublicKey) Fingerprint() uint32 {
	return uint32(C.CPublicKeyGetFingerprint(pk.pk))
}

// PublicKeyAggregate securely aggregates multiple public keys into one by
// exponentiating the keys with the pubKey hashes first
func PublicKeyAggregate(keys []PublicKey) (PublicKey, error) {
	// Get a C pointer to an array of public keys
	cPublicKeyArrayPtr := C.AllocPtrArray(C.size_t(len(keys)))
	defer C.FreePtrArray(cPublicKeyArrayPtr)

	// Loop thru each key and add the key C ptr to the array of ptrs at index
	for i, k := range keys {
		C.SetPtrArray(cPublicKeyArrayPtr, unsafe.Pointer(k.pk), C.int(i))
	}

	var key PublicKey
	var cDidErr C.bool
	key.pk = C.CPublicKeyAggregate(cPublicKeyArrayPtr, C.size_t(len(keys)), &cDidErr)
	if bool(cDidErr) {
		cErrMsg := C.GetLastErrorMsg()
		err := errors.New(C.GoString(cErrMsg))
		return PublicKey{}, err
	}

	runtime.SetFinalizer(&key, func(p *PublicKey) { p.Free() })
	return key, nil
}

// PublicKeyAggregateInsecure insecurely aggregates multiple public keys into
// one
func PublicKeyAggregateInsecure(keys []PublicKey) (PublicKey, error) {
	// Get a C pointer to an array of public keys
	cPublicKeyArrayPtr := C.AllocPtrArray(C.size_t(len(keys)))
	defer C.FreePtrArray(cPublicKeyArrayPtr)

	// Loop thru each key and add the key C ptr to the array of ptrs at index
	for i, k := range keys {
		C.SetPtrArray(cPublicKeyArrayPtr, unsafe.Pointer(k.pk), C.int(i))
	}

	var key PublicKey
	var cDidErr C.bool
	key.pk = C.CPublicKeyAggregateInsecure(cPublicKeyArrayPtr, C.size_t(len(keys)), &cDidErr)
	if bool(cDidErr) {
		cErrMsg := C.GetLastErrorMsg()
		err := errors.New(C.GoString(cErrMsg))
		return PublicKey{}, err
	}

	runtime.SetFinalizer(&key, func(p *PublicKey) { p.Free() })
	return key, nil
}

// Equal tests if one PublicKey object is equal to another
func (pk PublicKey) Equal(other PublicKey) bool {
	return bool(C.CPublicKeyIsEqual(pk.pk, other.pk))
}
