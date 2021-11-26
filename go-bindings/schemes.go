package blschia

// #cgo LDFLAGS: -lstdc++ -lgmp -lbls -lrelic_s -lsodium
// #cgo CXXFLAGS: -std=c++14
// #include <stdbool.h>
// #include <stdlib.h>
// #include "schemes.h"
// #include "privatekey.h"
// #include "elements.h"
// #include "blschia.h"
import "C"
import (
	"runtime"
	"unsafe"
)

// Signer is a signer interface
type Signer interface {
	Sign(sk *PrivateKey, msg []byte) *G2Element
}

// Generator is the interface that wraps the method needed to generate a private key
type Generator interface {
	KeyGen(seed []byte) (*PrivateKey, error)
}

// Verifier is the interface that wraps the methods needed to verifications
// the interface contains the method for direct verification
// and aggregation with verification
type Verifier interface {
	Verify(pk *G1Element, msg []byte, sig *G2Element) bool
	AggregateVerify(pks []*G1Element, msgs [][]byte, sig *G2Element) bool
}

// Aggregator is the interface that's described methods for aggregation public (G1) and private (g2) keys
type Aggregator interface {
	AggregatePubKeys(pks ...*G1Element) *G1Element
	AggregateSigs(sigs ...*G2Element) *G2Element
}

// Deriver ...
type Deriver interface {
	DeriveChildSk(sk *PrivateKey, index int) *PrivateKey
	DeriveChildSkUnhardened(sk *PrivateKey, index int) *PrivateKey
	DeriveChildPkUnhardened(el *G1Element, index int) *G1Element
}

// Scheme  a schema interface
type Scheme interface {
	Signer
	Generator
	Verifier
	Aggregator
	Deriver
}

type coreMLP struct {
	val C.CCoreMPL
}

// KeyGen returns a new generated PrivateKey using passed a seed data
func (s *coreMLP) KeyGen(seed []byte) (*PrivateKey, error) {
	cSeedPtr := C.CBytes(seed)
	defer C.free(cSeedPtr)
	var cDidErr C.bool
	sk := PrivateKey{
		val: C.CCoreMPLKeyGen(s.val, cSeedPtr, C.size_t(len(seed)), &cDidErr),
	}
	if cDidErr {
		return nil, errFromC()
	}
	runtime.SetFinalizer(&sk, func(sk *PrivateKey) { sk.Free() })
	return &sk, nil
}

// SkToG1 converts PrivateKey into G1Element (public key)
func (s *coreMLP) SkToG1(sk *PrivateKey) *G1Element {
	return &G1Element{
		val: C.CCoreMPSkToG1(s.val, sk.val),
	}
}

// Sign signs a message using a PrivateKey and returns the G2Element as a signature
func (s *coreMLP) Sign(sk *PrivateKey, msg []byte) *G2Element {
	cMsgPtr := C.CBytes(msg)
	defer C.free(cMsgPtr)
	sig := G2Element{
		val: C.CCoreMPLSign(s.val, sk.val, cMsgPtr, C.size_t(len(msg))),
	}
	runtime.SetFinalizer(&sig, func(sig *G2Element) { sig.Free() })
	return &sig
}

// Verify verifies a signature for a message with a G1Element as a public key
func (s *coreMLP) Verify(pk *G1Element, msg []byte, sig *G2Element) bool {
	cMsgPtr := C.CBytes(msg)
	defer C.free(cMsgPtr)
	isVerified := bool(C.CCoreMPLVerify(s.val, pk.val, cMsgPtr, C.size_t(len(msg)), sig.val))
	return isVerified
}

// AggregatePubKeys returns a new G1Element (public key) as an aggregated public keys
func (s *coreMLP) AggregatePubKeys(pks ...*G1Element) *G1Element {
	cPkArrPtr := cAllocPubKeys(pks...)
	defer C.FreePtrArray(cPkArrPtr)
	aggSig := G1Element{
		val: C.CCoreMPLAggregatePubKeys(s.val, cPkArrPtr, C.size_t(len(pks))),
	}
	runtime.SetFinalizer(&aggSig, func(aggSig *G1Element) { aggSig.Free() })
	return &aggSig
}

// AggregateSigs returns a new G1Element (aggregated public keys)
// as a result of the aggregation of the passed public keys
func (s *coreMLP) AggregateSigs(sigs ...*G2Element) *G2Element {
	cSigArrayPtr := C.AllocPtrArray(C.size_t(len(sigs)))
	defer C.FreePtrArray(cSigArrayPtr)
	for i, sig := range sigs {
		C.SetPtrArray(cSigArrayPtr, unsafe.Pointer(sig.val), C.int(i))
	}
	aggSig := G2Element{
		val: C.CCoreMPLAggregateSigs(s.val, cSigArrayPtr, C.size_t(len(sigs))),
	}
	runtime.SetFinalizer(&aggSig, func(aggSig *G2Element) { aggSig.Free() })
	return &aggSig
}

// DeriveChildSk ...
func (s *coreMLP) DeriveChildSk(sk *PrivateKey, index int) *PrivateKey {
	res := PrivateKey{
		val: C.CCoreMPLDeriveChildSk(s.val, sk.val, C.uint32_t(index)),
	}
	runtime.SetFinalizer(&res, func(res *PrivateKey) { res.Free() })
	return &res
}

// DeriveChildSkUnhardened ...
func (s *coreMLP) DeriveChildSkUnhardened(sk *PrivateKey, index int) *PrivateKey {
	res := PrivateKey{
		val: C.CCoreMPLDeriveChildSkUnhardened(s.val, sk.val, C.uint32_t(index)),
	}
	runtime.SetFinalizer(&res, func(res *PrivateKey) { res.Free() })
	return &res
}

// DeriveChildPkUnhardened ...
func (s *coreMLP) DeriveChildPkUnhardened(el *G1Element, index int) *G1Element {
	res := G1Element{
		val: C.CCoreMPLDeriveChildPkUnhardened(s.val, el.val, C.uint32_t(index)),
	}
	runtime.SetFinalizer(&res, func(res *G1Element) { res.Free() })
	return &res
}

// AggregateVerify verifies the aggregated signature for a list of messages with public keys
// returns true if the signature is a valid otherwise returns false
func (s *coreMLP) AggregateVerify(pks []*G1Element, msgs [][]byte, sig *G2Element) bool {
	cPkArrPtr := cAllocPubKeys(pks...)
	defer C.FreePtrArray(cPkArrPtr)
	cMsgArrPtr, msgLens := cAllocMsgs(msgs)
	defer C.FreePtrArray(cMsgArrPtr)
	val := C.CCoreMPLAggregateVerify(
		s.val,
		cPkArrPtr,
		C.size_t(len(pks)),
		cMsgArrPtr,
		unsafe.Pointer(&msgLens[0]),
		C.size_t(len(msgs)),
		sig.val,
	)
	return bool(val)
}

// BasicSchemeMPL represents bls::BasicSchemeMPL (basic scheme using minimum public key sizes)
type BasicSchemeMPL struct {
	coreMLP
}

// NewBasicSchemeMPL returns a new BasicSchemeMPL
func NewBasicSchemeMPL() *BasicSchemeMPL {
	scheme := BasicSchemeMPL{
		coreMLP{
			val: C.NewCBasicSchemeMPL(),
		},
	}
	runtime.SetFinalizer(&scheme, func(scheme *BasicSchemeMPL) { scheme.Free() })
	return &scheme
}

// AggregateVerify verifies the aggregated signature for a list of messages with public keys
func (s *BasicSchemeMPL) AggregateVerify(pks []*G1Element, msgs [][]byte, sig *G2Element) bool {
	cPkArrPtr := cAllocPubKeys(pks...)
	defer C.FreePtrArray(cPkArrPtr)
	cMsgArrPtr, msgLens := cAllocMsgs(msgs)
	defer C.FreePtrArray(cMsgArrPtr)
	val := C.CBasicSchemeMPLAggregateVerify(
		s.val,
		cPkArrPtr,
		C.size_t(len(pks)),
		cMsgArrPtr,
		unsafe.Pointer(&msgLens[0]),
		C.size_t(len(msgs)),
		sig.val,
	)
	return bool(val)
}

// Free releases a memory of bls::BasicSchemeMPL
func (s *BasicSchemeMPL) Free() {
	C.CBasicSchemeMPLFree(s.val)
}

// AugSchemeMPL represents bls::AugSchemeMPL (augmented scheme using)
// augmented should be enough for most use cases
type AugSchemeMPL struct {
	coreMLP
}

// NewAugSchemeMPL returns a new AugSchemeMPL
func NewAugSchemeMPL() *AugSchemeMPL {
	scheme := AugSchemeMPL{
		coreMLP: coreMLP{
			val: C.NewCAugSchemeMPL(),
		},
	}
	runtime.SetFinalizer(&scheme, func(scheme *AugSchemeMPL) { scheme.Free() })
	return &scheme
}

// Sign signs a message with a PrivateKey
func (s *AugSchemeMPL) Sign(sk *PrivateKey, msg []byte) *G2Element {
	cMsgPtr := C.CBytes(msg)
	defer C.free(cMsgPtr)
	sig := G2Element{
		val: C.CAugSchemeMPLSign(s.val, sk.val, cMsgPtr, C.size_t(len(msg))),
	}
	runtime.SetFinalizer(&sig, func(sig *G2Element) { sig.Free() })
	return &sig
}

// SignPrepend ...
func (s *AugSchemeMPL) SignPrepend(sk *PrivateKey, msg []byte, prepPk *G1Element) *G2Element {
	sig := G2Element{
		val: C.CAugSchemeMPLSignPrepend(s.val, sk.val, C.CBytes(msg), C.size_t(len(msg)), prepPk.val),
	}
	runtime.SetFinalizer(&sig, func(sig *G2Element) { sig.Free() })
	return &sig
}

// Verify verifies a G2Element (signature) for a message with a G1Element (public key)
func (s *AugSchemeMPL) Verify(pk *G1Element, msg []byte, sig *G2Element) bool {
	cMsgPtr := C.CBytes(msg)
	defer C.free(cMsgPtr)
	val := C.CAugSchemeMPLVerify(s.val, pk.val, cMsgPtr, C.size_t(len(msg)), sig.val)
	return bool(val)
}

// AggregateVerify verifies the aggregated signature for a list of messages with public keys
func (s *AugSchemeMPL) AggregateVerify(pks []*G1Element, msgs [][]byte, sig *G2Element) bool {
	cPkArrPtr := cAllocPubKeys(pks...)
	defer C.FreePtrArray(cPkArrPtr)
	cMsgArrPtr, msgLens := cAllocMsgs(msgs)
	defer C.FreePtrArray(cMsgArrPtr)
	val := C.CAugSchemeMPLAggregateVerify(
		s.val,
		cPkArrPtr,
		C.size_t(len(pks)),
		cMsgArrPtr,
		unsafe.Pointer(&msgLens[0]),
		C.size_t(len(msgs)),
		sig.val,
	)
	return bool(val)
}

// Free releases allocated memory bls::AugSchemeMPL
func (s *AugSchemeMPL) Free() {
	C.CAugSchemeMPLFree(s.val)
}

// PopSchemeMPL represents bls::PopSchemeMPL (proof of possession scheme)
// proof of possession can be used where verification must be fast
type PopSchemeMPL struct {
	coreMLP
}

// NewPopSchemeMPL returns a new bls::PopSchemeMPL
func NewPopSchemeMPL() *PopSchemeMPL {
	scheme := PopSchemeMPL{
		coreMLP: coreMLP{
			val: C.NewCPopSchemeMPL(),
		},
	}
	runtime.SetFinalizer(&scheme, func(scheme *PopSchemeMPL) { scheme.Free() })
	return &scheme
}

// PopProve ...
func (s *PopSchemeMPL) PopProve(sk *PrivateKey) *G2Element {
	sig := G2Element{
		val: C.CPopSchemeMPLPopProve(s.val, sk.val),
	}
	runtime.SetFinalizer(&sig, func(sig *G2Element) { sig.Free() })
	return &sig
}

// PopVerify ...
func (s *PopSchemeMPL) PopVerify(pk *G1Element, sig *G2Element) bool {
	return bool(C.CPopSchemeMPLPopVerify(s.val, pk.val, sig.val))
}

// FastAggregateVerify uses for a fast verification
func (s *PopSchemeMPL) FastAggregateVerify(pks []*G1Element, msg []byte, sig *G2Element) bool {
	msgPtr := C.CBytes(msg)
	cPkArrPtr := cAllocPubKeys(pks...)
	defer C.FreePtrArray(cPkArrPtr)
	isVerified := C.CPopSchemeMPLFastAggregateVerify(
		s.val,
		cPkArrPtr,
		C.size_t(len(pks)),
		msgPtr,
		C.size_t(len(msg)),
		sig.val,
	)
	return bool(isVerified)
}

// Free ...
func (s *PopSchemeMPL) Free() {
	C.CPopSchemeMPLFree(s.val)
}

func cAllocPubKeys(pks ...*G1Element) *unsafe.Pointer {
	arr := C.AllocPtrArray(C.size_t(len(pks)))
	for i, pk := range pks {
		C.SetPtrArray(arr, unsafe.Pointer(pk.val), C.int(i))
	}
	return arr
}

func cAllocMsgs(msgs [][]byte) (*unsafe.Pointer, []int) {
	msgLens := make([]int, len(msgs))
	cMsgArrPtr := C.AllocPtrArray(C.size_t(len(msgs)))
	for i, msg := range msgs {
		cMsgPtr := C.CBytes(msg)
		C.SetPtrArray(cMsgArrPtr, unsafe.Pointer(cMsgPtr), C.int(i))
		msgLens[i] = len(msg)
	}
	return cMsgArrPtr, msgLens
}
