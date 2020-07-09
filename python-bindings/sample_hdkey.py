import hashlib
import blspy
from copy import deepcopy

"""
class BLSPublicHDKey(blspy.G1Element):
    @classmethod
    def convert(cls, blob):
        blob.__class__ = cls
        return blob

    def child(self, destination: bytes):
        return BLSPublicHDKey.convert(blspy.HDCKD.g1_to_g1(self, destination))

    def fingerprint(self):
        return hashlib.sha256(bytes(self)).digest()[-4:]


class BLSPrivateHDKey(blspy.PrivateKey):
    @classmethod
    def _convert(cls, blob):
        blob.__class__ = cls
        return blob

    def __init__(self, sk: blspy.PrivateKey):
        self = BLSPrivateHDKey._convert(sk)

    def child(self, destination: bytes, hardened: bool = False):
        return BLSPrivateHDKey.convert(
            blspy.HDCKD.sk_to_sk_MPS(self, destination, hardened)
        )

    def fingerprint(self):
        return hashlib.sha256(bytes(self)).digest()[-4:]
"""

sk = blspy.PrivateKey.from_bytes(bytes([0] * (32 - 3) + [1, 2, 3]))
print("!", sk)

for x in range(2, 10):
    A = list(range(1, x + 1))
    print("!A", A)
    out1 = blspy.HDCKD.sk_to_sk_MPS(sk, A, False)
    print("out", out1)

# sk2 = blspy.PrivateKey.from_bytes(bytes([1, 2, 3]))
# out2 = blspy.HDCKD.sk_to_sk_MPS(sk2, [1, 2, 3], False)

# print("!", sk, sk2)
# print("A", out1, out2)

# sk = blspy.PrivateKey.from_bytes(bytes([1, 2, 3]))
# g1 = blspy.G1Element.generator() * 3
# out2 = blspy.HDCKD.g1_to_g1(g1, [1, 2, 3])

# esk_c = esk.child(bytes([1, 2, 3, 4]), False)
# esk_c2 = esk_c.child(bytes([1, 2, 3, 4]), True)
