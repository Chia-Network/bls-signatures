from blspy import (
    G1Element as G1,
    G2Element as G2,
    BasicScheme as BSc,
    AugScheme as ASc,
    PopScheme as PSc,
    PrivateKey,
)

from py_ecc.bls import (
    G2Basic,
    G2MessageAugmentation as G2MA,
    G2ProofOfPossession as G2Pop,
)
from py_ecc.fields import (
    optimized_bls12_381_FQ as FQ,
    optimized_bls12_381_FQ2 as FQ2,
    optimized_bls12_381_FQ12 as FQ12,
    optimized_bls12_381_FQP as FQP,
)

M = set()
for secret in range(50):
    secret_bytes = bytes([0] * 31 + [secret])
    sk = PrivateKey.from_bytes(secret_bytes, 1)

    pk1 = BSc.sk_to_g1(sk)
    pk2 = G2Basic.SkToPk(secret)
    # print(str(pk1))
    # print(str(pk2.hex()))
    A = str(pk1)
    B = str(pk2.hex())
    if 1:  # A != B:
        X = int(A[:1], 16)
        X = bin(X)[2:].zfill(4)[:3]
        Y = int(B[:1], 16)
        Y = bin(Y)[2:].zfill(4)[:3]
        # M.add((X, Y))
        print(X, Y, X == Y)
# for X, Y in M:
#    if X != Y:
#        print(X, Y)
print("done")

