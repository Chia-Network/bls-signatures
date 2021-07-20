package blschia

// #cgo LDFLAGS: -L../build -lbls -lstdc++
// #cgo CXXFLAGS: -std=c++14 -I../src -I../build/contrib/relic/include -I../contrib/relic/include
// #include <stdbool.h>
// #include <stdlib.h>
// #include "threshold.h"
// #include "blschia.h"
import "C"
import (
	"math/big"
	"runtime"
	"unsafe"
)

// ThresholdCreate constructs a PrivateKey with associated data suitable for a
// threshold signature scheme
func ThresholdCreate(T, N int) (PrivateKey, []PublicKey, []PrivateKey) {
	if (T < 1) || (T > N) {
		panic("threshold parameter T must be between 1 and N")
		// err not panic?
	}

	// There are T polynomials / commitments
	commitmentsPtr := C.AllocPtrArray(C.size_t(T))
	defer C.FreePtrArray(commitmentsPtr)

	// There are N secret fragments
	secretFragmentsPtr := C.AllocPtrArray(C.size_t(N))
	defer C.FreePtrArray(secretFragmentsPtr)

	var sk PrivateKey
	sk.sk = C.CThresholdCreate(commitmentsPtr, secretFragmentsPtr, C.size_t(T), C.size_t(N))
	runtime.SetFinalizer(&sk, func(p *PrivateKey) { p.Free() })

	// Loop thru each commitment and get the value (copy bytes) and create a
	// new PublicKey object
	commitments := make([]PublicKey, T)
	for i := 0; i < T; i++ {
		ptr := C.GetPtrAtIndex(commitmentsPtr, C.int(i))
		defer C.free(ptr)
		var tempPk PublicKey
		tempPk.pk = C.CPublicKey(ptr)
		pkBytes := tempPk.Serialize()
		commitments[i], _ = PublicKeyFromBytes(pkBytes)
	}

	// Loop thru each fragment and get the value (copy bytes) and create a new
	// PrivateKey object
	secretFragments := make([]PrivateKey, N)
	for i := 0; i < N; i++ {
		ptr := C.GetPtrAtIndex(secretFragmentsPtr, C.int(i))
		defer C.free(ptr)
		var tempSk PrivateKey
		tempSk.sk = C.CPrivateKey(ptr)
		skBytes := tempSk.Serialize()
		secretFragments[i], _ = PrivateKeyFromBytes(skBytes, true)
	}

	return sk, commitments, secretFragments
}

// ThresholdLagrangeCoeffsAtZero returns lagrange coefficients of a polynomial
// evaluated at zero.
//
// If we have T points (players[i], P(players[i])), it interpolates to a degree
// T-1 polynomial P.  The returned coefficients are such that P(0) = sum_i
// res[i] * P(players[i]).
func ThresholdLagrangeCoeffsAtZero(players []int, T int) []*big.Int {
	// Get a C pointer to players array
	cPlayersPtr := C.AllocIntPtr(C.size_t(len(players)))
	defer C.FreeIntPtr(cPlayersPtr)
	for i, value := range players {
		C.SetIntPtrVal(cPlayersPtr, C.size_t(value), C.int(i))
	}

	// returns a **, or a *unsafe.Pointer
	arrPtr := C.CThresholdLagrangeCoeffsAtZero(cPlayersPtr, C.size_t(T))
	defer C.FreePtrArray(arrPtr)

	res := make([]*big.Int, T)
	for i := 0; i < T; i++ {
		// get the singular pointer at index
		ptr := C.GetPtrAtIndex(arrPtr, C.int(i))
		val := C.GoBytes(ptr, C.CPrivateKeySizeBytes())
		res[i] = new(big.Int).SetBytes(val)
	}

	return res
}

// ThresholdVerifySecretFragment returns true iff the secretFragment from the
// given player matches their given commitment to a polynomial.
func ThresholdVerifySecretFragment(player int, secretFragment PrivateKey, commitments []PublicKey, T int) bool {
	// Get a C pointer to an array of public keys
	commitmentsPtr := C.AllocPtrArray(C.size_t(len(commitments)))
	defer C.FreePtrArray(commitmentsPtr)
	// Loop thru each publickey and add the pointer to it, to the C pointer
	// array at the given index.
	for i, key := range commitments {
		C.SetPtrArray(commitmentsPtr, unsafe.Pointer(key.pk), C.int(i))
	}

	val := C.CThresholdVerifySecretFragment(
		C.size_t(player),
		secretFragment.sk,
		commitmentsPtr,
		C.size_t(len(commitments)),
		C.size_t(T),
	)
	return bool(val)
}

// ThresholdSignWithCoefficient signs a message with lagrange coefficients.
//
// The T signatures signed this way (with the same parameters players and T)
// can be multiplied together to create a final signature for that message.
func ThresholdSignWithCoefficient(sk PrivateKey, message []byte, player int, players []int, T int) InsecureSignature {
	// Get a C pointer to bytes
	cMessagePtr := C.CBytes(message)
	defer C.free(cMessagePtr)

	// Get a C pointer to players array
	cPlayersPtr := C.AllocIntPtr(C.size_t(len(players)))
	defer C.FreeIntPtr(cPlayersPtr)
	for i, value := range players {
		C.SetIntPtrVal(cPlayersPtr, C.size_t(value), C.int(i))
	}

	var sig InsecureSignature
	sig.sig = C.CThresholdSignWithCoefficient(sk.sk, cMessagePtr,
		C.size_t(len(message)), C.size_t(player), cPlayersPtr, C.size_t(T))
	runtime.SetFinalizer(&sig, func(p *InsecureSignature) { p.Free() })

	return sig
}

// ThresholdAggregateUnitSigs aggregates signatures (that have not been
// multiplied by lagrange coefficients) into a final signature for the master
// private key.
func ThresholdAggregateUnitSigs(sigs []InsecureSignature, message []byte, players []int, T int) InsecureSignature {
	// Get a C pointer to bytes
	cMessagePtr := C.CBytes(message)
	defer C.free(cMessagePtr)

	// Get a C pointer to players array
	cPlayersPtr := C.AllocIntPtr(C.size_t(len(players)))
	defer C.FreeIntPtr(cPlayersPtr)
	for i, value := range players {
		C.SetIntPtrVal(cPlayersPtr, C.size_t(value), C.int(i))
	}

	// Get a C pointer to an array of signatures
	signaturesPtr := C.AllocPtrArray(C.size_t(len(sigs)))
	defer C.FreePtrArray(signaturesPtr)
	// Loop thru each signature and add the pointer to it, to the C pointer array at
	// the given index.
	for i, sig := range sigs {
		C.SetPtrArray(signaturesPtr, unsafe.Pointer(sig.sig), C.int(i))
	}

	var sig InsecureSignature
	sig.sig = C.CThresholdAggregateUnitSigs(signaturesPtr, C.size_t(len(sigs)),
		cMessagePtr, C.size_t(len(message)), cPlayersPtr, C.size_t(T))
	runtime.SetFinalizer(&sig, func(p *InsecureSignature) { p.Free() })

	return sig
}
