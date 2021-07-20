package blschia_test

import (
	"testing"

	bls "github.com/nmarley/bls-signatures/go-bindings"
)

func TestThreshold(t *testing.T) {
	// To initialize a T of N threshold key under a
	// Joint-Feldman scheme:
	T := 2
	N := 3

	commitments := make([][]bls.PublicKey, N)
	fragments := make([][]bls.PrivateKey, N)
	secrets := make([]bls.PrivateKey, N)

	// Step 1 : ThresholdCreate
	for player := 0; player < N; player++ {
		sk, commits, frags := bls.ThresholdCreate(T, N)
		for j, frag := range frags {
			fragments[j] = append(fragments[j], frag)
		}
		commitments[player] = commits
		secrets[player] = sk
	}

	// Step 2 : ThresholdVerifySecretFragment
	for source := 1; source <= N; source++ {
		for target := 1; target <= N; target++ {
			didVerify := bls.ThresholdVerifySecretFragment(
				target,
				fragments[target-1][source-1],
				commitments[source-1],
				T,
			)

			if !didVerify {
				t.Error("threshold fragment did not verify")
			}
		}
	}

	// Step 3 : masterPubkey = AggregatePublicKeys(...)
	//          secretShare = AggregatePrivateKeys(...)
	pksToAggregate := make([]bls.PublicKey, len(commitments))
	for i, cpoly := range commitments {
		pksToAggregate[i] = cpoly[0]
	}
	masterPubKey, err := bls.PublicKeyAggregateInsecure(pksToAggregate)
	if err != nil {
		t.Errorf("got unexpected error: %v", err.Error())
	}

	secretShares := make([]bls.PrivateKey, len(fragments))
	for i, row := range fragments {
		ss, err := bls.PrivateKeyAggregateInsecure(row)
		if err != nil {
			t.Errorf("got unexpected error: %v", err.Error())
		}
		secretShares[i] = ss
	}
	masterPrivateKey, err := bls.PrivateKeyAggregateInsecure(secrets)
	if err != nil {
		t.Errorf("got unexpected error: %v", err.Error())
	}

	// Same values as in C++ test : 100, 2, 254, 88, 90, 45, 23
	msg := []byte{
		0x64, 0x02, 0xfe, 0x58, 0x5a, 0x2d, 0x17,
	}
	hash := Sha256(msg)

	signatureActual := masterPrivateKey.Sign(hash)

	if !signatureActual.Verify() {
		t.Error("sig did not verify")
	}

	// Step 4a : sigShare = Threshold::SignWithCoefficient(...)
	//           signature = InsecureSignature::Aggregate(...)

	// players 1 and 3 sign
	players := []int{1, 3}
	// As we have verified the coefficients through the commitments given,
	// using InsecureSignature is okay.
	sigShareC1 := bls.ThresholdSignWithCoefficient(secretShares[0], msg, 1, players, T)
	sigShareC3 := bls.ThresholdSignWithCoefficient(secretShares[2], msg, 3, players, T)
	signature, _ := bls.InsecureSignatureAggregate([]bls.InsecureSignature{
		sigShareC1, sigShareC3,
	})
	if !signature.Verify([][]byte{hash}, []bls.PublicKey{masterPubKey}) {
		t.Error("signature did not verify")
	}

	// Step 4b : sigShare = secretShare.SignInsecure(...)
	//           signature = Threshold::AggregateUnitSigs(...)

	// players 1 and 3 sign
	sigShareU1 := secretShares[0].SignInsecure(msg)
	sigShareU3 := secretShares[2].SignInsecure(msg)
	signature2 := bls.ThresholdAggregateUnitSigs(
		[]bls.InsecureSignature{sigShareU1, sigShareU3},
		msg,
		players,
		T,
	)
	if !signature2.Verify([][]byte{hash}, []bls.PublicKey{masterPubKey}) {
		t.Error("signature2 did not verify")
	}
}
