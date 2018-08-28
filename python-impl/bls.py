from ec import (generator_Fq, hash_to_point_Fq2, default_ec,
                default_ec_twist,
                hash_to_point_prehashed_Fq2, y_for_x,
                AffinePoint)
from fields import Fq, Fq2, Fq12
from util import hmac256, hash256
from pairing import ate_pairing_multi


class BLSPublicKey:
    PUBLIC_KEY_SIZE = 48

    def __init__(self, value):
        self.value = value

    @staticmethod
    def from_bytes(buffer):
        x = int.from_bytes(buffer, "big")
        y = y_for_x(Fq(default_ec.q, x))
        return BLSPublicKey(AffinePoint(x, y, False, default_ec).to_jacobian())

    @staticmethod
    def from_g1(g1_el):
        return BLSPublicKey(g1_el)

    def get_fingerprint(self):
        ser = self.serialize()
        return int.from_bytes(hash256(ser)[:4], "big")

    def serialize(self):
        value_affine = self.value.to_affine()
        x_bytes = bytearray(int(value_affine.x).to_bytes(
                self.PUBLIC_KEY_SIZE, "big"))
        y_bytes = int(value_affine.y).to_bytes(self.PUBLIC_KEY_SIZE, "big")
        if (y_bytes[0] & 0x01 != 0x00):
            x_bytes[0] |= 0x80
        return bytes(x_bytes)

    def __str__(self):
        return "BLSPublicKey(" + self.value.to_affine().__str__() + ")"

    def __repr__(self):
        return "BLSPublicKey(" + self.value.to_affine().__repr__() + ")"


class BLSPrivateKey:
    PRIVATE_KEY_SIZE = 32

    def __init__(self, value):
        self.value = value

    @staticmethod
    def from_bytes(buffer):
        return BLSPrivateKey(int.from_bytes(buffer, "big"))

    @staticmethod
    def from_seed(seed):
        # "BLS private key seed" in ascii
        hmac_key = bytes([66, 76, 83, 32, 112, 114, 105, 118, 97, 116, 101,
                          32, 107, 101, 121, 32, 115, 101, 101, 100])

        hashed = hmac256(seed, hmac_key)
        return BLSPrivateKey(int.from_bytes(hashed, "big") % default_ec.n)

    def get_public_key(self):
        return BLSPublicKey.from_g1((self.value * generator_Fq())
                                    .to_jacobian())

    def sign(self, m):
        r = hash_to_point_Fq2(m).to_jacobian()
        return BLSSignature.from_g2(self.value * r)

    def sign_prehashed(self, h):
        r = hash_to_point_prehashed_Fq2(h).to_jacobian()
        return BLSSignature.from_g2(self.value * r)

    def serialize(self):
        return int(self.value).to_bytes(self.PRIVATE_KEY_SIZE, "big")

    def __str__(self):
        return "BLSPrivateKey(" + self.value.__str__() + ")"

    def __repr__(self):
        return "BLSPrivateKey(" + self.value.__repr__() + ")"


class AggregationInfo:
    def __init__(self, tree, message_hashes, pks):
        self.tree = tree
        self.message_hashes = message_hashes
        self.pks = pks

    @staticmethod
    def from_msg_hash(pk, message_hash):
        tree = {}
        serialized = message_hash + pk.serialize()
        tree[serialized] = 1
        return AggregationInfo(tree, [message_hash], [pk])

    @staticmethod
    def from_msg(pk, message):
        return AggregationInfo.from_msg_hash(hash256(message))


class BLSSignature:
    SIGNATURE_SIZE = 96

    def __init__(self, value):
        self.value = value
        self.aggregation_info = None

    @staticmethod
    def from_bytes(buffer):
        x0 = int.from_bytes(buffer[:48], "big")
        x1 = int.from_bytes(buffer[48:], "big")
        x = Fq2(default_ec.q, Fq(default_ec.q, x0), Fq(default_ec.q, x1))
        y = y_for_x(x)
        return BLSPublicKey(AffinePoint(x, y, False, default_ec).to_jacobian())

    @staticmethod
    def from_g2(g2_el):
        return BLSSignature(g2_el)

    def serialize(self):
        value_affine = self.value.to_affine()
        x_bytes = bytearray(int(value_affine.x[0]).to_bytes(
                    self.SIGNATURE_SIZE // 2, "big") +
                int(value_affine.x[1]).to_bytes(self.SIGNATURE_SIZE//2, "big"))

        ys = y_for_x(value_affine.x, default_ec_twist, Fq2)
        if (ys[1] == value_affine.y):
            x_bytes[0] |= 0xf0
        return bytes(x_bytes)

    def __str__(self):
        return "BLSSignature(" + self.value.to_affine().__str__() + ")"

    def __repr__(self):
        return "BLSSignature(" + self.value.to_affine().__repr__() + ")"


class BLS:
    @staticmethod
    def aggregate_sigs(signatures):
        q = default_ec.q
        agg_sig = (AffinePoint(Fq2.zero(q), Fq2.zero(q), True, default_ec)
                   .to_jacobian())

        for sig in signatures:
            agg_sig += sig.value
        return BLSSignature.from_g2(agg_sig)

    @staticmethod
    def verify(message, pk, signature):
        message_hash = hash_to_point_Fq2(message)
        g1 = -1 * generator_Fq()

        Ps = [g1, pk.value.to_affine()]
        Qs = [signature.value.to_affine(), message_hash]
        res = ate_pairing_multi(Ps, Qs, default_ec)
        return res == Fq12.one(default_ec.q)


"""
Copyright 2018 Chia Network Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
