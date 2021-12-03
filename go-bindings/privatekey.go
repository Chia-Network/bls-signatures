package blschia

// #include <stdbool.h>
// #include <stdlib.h>
// #include "privatekey.h"
// #include "blschia.h"
import "C"
import (
	"encoding/hex"
	"runtime"
	"unsafe"
)

// PrivateKey represents a bls::PrivateKey (32 byte integer)
type PrivateKey struct {
	val C.CPrivateKey
}

// PrivateKeyFromBytes returns a new PrivateKey from bytes
// this method allocates the new bls::PrivateKey object and keeps its pointer
func PrivateKeyFromBytes(data []byte, modOrder bool) (*PrivateKey, error) {
	cBytesPtr := cAllocBytes(data)
	defer C.SecFree(cBytesPtr)
	var cDidErr C.bool
	sk := PrivateKey{
		val: C.CPrivateKeyFromBytes(cBytesPtr, C.bool(modOrder), &cDidErr),
	}
	if bool(cDidErr) {
		return nil, errFromC()
	}
	runtime.SetFinalizer(&sk, func(p *PrivateKey) { p.free() })
	return &sk, nil
}

// G1Element returns a G1Element (public key) using a state of the current private key
// this method is a binding of the bls::PrivateKey::G1Element
func (sk *PrivateKey) G1Element() (*G1Element, error) {
	var cDidErr C.bool
	el := G1Element{
		val: C.CPrivateKeyGetG1Element(sk.val, &cDidErr),
	}
	if bool(cDidErr) {
		return nil, errFromC()
	}
	runtime.SetFinalizer(&el, func(el *G1Element) { el.free() })
	return &el, nil
}

// G2Element returns a G2Element (signature) using a state of the current private key
// this method is a binding of the bls::PrivateKey::G2Element
func (sk *PrivateKey) G2Element() (*G2Element, error) {
	var cDidErr C.bool
	el := G2Element{
		val: C.CPrivateKeyGetG2Element(sk.val, &cDidErr),
	}
	runtime.SetFinalizer(&el, func(el *G2Element) { el.free() })
	if bool(cDidErr) {
		return nil, errFromC()
	}
	return &el, nil
}

// G2Power returns a power of G2Element (signature)
// this method is a binding of the bls::PrivateKey::G2Power
func (sk *PrivateKey) G2Power(el *G2Element) *G2Element {
	sig := G2Element{
		val: C.CPrivateKeyGetG2Power(sk.val, el.val),
	}
	runtime.SetFinalizer(&sig, func() { sig.free() })
	return &sig
}

// Serialize returns the byte representation of the private key
// this method is a binding of the bls::PrivateKey::Serialize
func (sk *PrivateKey) Serialize() []byte {
	ptr := C.CPrivateKeySerialize(sk.val)
	defer C.SecFree(ptr)
	return C.GoBytes(ptr, C.int(C.CPrivateKeySizeBytes()))
}

// PrivateKeyAggregate securely aggregates multiple private keys into one
// this method is a binding of the bls::PrivateKey::Aggregate
func PrivateKeyAggregate(sks ...*PrivateKey) *PrivateKey {
	cPrivKeyArrPtr := C.AllocPtrArray(C.size_t(len(sks)))
	for i, privKey := range sks {
		C.SetPtrArray(cPrivKeyArrPtr, unsafe.Pointer(privKey.val), C.int(i))
	}
	defer C.FreePtrArray(cPrivKeyArrPtr)
	sk := PrivateKey{
		val: C.CPrivateKeyAggregate(cPrivKeyArrPtr, C.size_t(len(sks))),
	}
	runtime.SetFinalizer(&sk, func(p *PrivateKey) { p.free() })
	return &sk
}

// EqualTo tests if one PrivateKey is equal to another
// this method is the binding of the equality operation
func (sk *PrivateKey) EqualTo(other *PrivateKey) bool {
	return bool(C.CPrivateKeyIsEqual(sk.val, other.val))
}

// HexString returns a hex string representation of serialized data
func (sk *PrivateKey) HexString() string {
	return hex.EncodeToString(sk.Serialize())
}

// free calls CPrivateKeyFree "C" function to release a memory allocated for bls::PrivateKey
func (sk *PrivateKey) free() {
	C.CPrivateKeyFree(sk.val)
}
