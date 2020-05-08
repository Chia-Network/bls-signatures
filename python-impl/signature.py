from copy import deepcopy
from ec import (AffinePoint, JacobianPoint, default_ec, generator_Fq,
                default_ec_twist, y_for_x, hash_to_point_prehashed_Fq2)
from fields import Fq, Fq2, Fq12
from util import hash256
from aggregation_info import AggregationInfo
from bls import BLS
from pairing import ate_pairing_multi


class Signature:
    """
    Signatures are G2 elements, which are elliptic curve points (x, y), where
    each x, y is a (2*381) bit Fq2 element. The serialized represenentation is
    just the x value, and thus 96 bytes. (With the 1st bit determining the
    valid y).
    """
    SIGNATURE_SIZE = 96

    def __init__(self, value, aggregation_info=None):
        self.value = value
        self.aggregation_info = aggregation_info

    @staticmethod
    def from_bytes(buffer, aggregation_info=None):
        use_big_y = buffer[0] & 0x80
        prepend = buffer[0] & 0x40
        if prepend:
            raise Exception("Should not have prepend bit set")

        buffer = bytes([buffer[0] & 0x1f]) + buffer[1:]

        x0 = int.from_bytes(buffer[:48], "big")
        x1 = int.from_bytes(buffer[48:], "big")
        x = Fq2(default_ec.q, Fq(default_ec.q, x0), Fq(default_ec.q, x1))
        ys = y_for_x(x, default_ec_twist, Fq2)
        y = ys[0]
        if ((use_big_y and ys[1][1] > default_ec.q // 2) or
                (not use_big_y and ys[1][1] < default_ec.q // 2)):
            y = ys[1]

        return Signature(AffinePoint(x, y, False, default_ec_twist)
                         .to_jacobian(),
                         aggregation_info)

    @staticmethod
    def from_g2(g2_el, aggregation_info=None):
        return Signature(g2_el, aggregation_info)

    def divide_by(self, divisor_signatures):
        """
        Signature division (elliptic curve subtraction). This is useful if
        you have already verified parts of the tree, since verification
        of the resulting quotient signature will be faster (less pairings
        have to be perfomed).

        This function Divides an aggregate signature by other signatures
        in the aggregate trees. A signature can only be divided if it is
        part of the subset, and all message/public key pairs in the
        aggregationInfo for the divisor signature are unique. i.e you cannot
        divide s1 / s2, if s2 is an aggregate signature containing m1,pk1,
        which is also present somewhere else in s1's tree. Note, s2 itself
        does not have to be unique.
        """
        message_hashes_to_remove = []
        pubkeys_to_remove = []
        prod = JacobianPoint(Fq2.one(default_ec.q), Fq2.one(default_ec.q),
                             Fq2.zero(default_ec.q), True, default_ec)
        for divisor_sig in divisor_signatures:
            pks = divisor_sig.aggregation_info.public_keys
            message_hashes = divisor_sig.aggregation_info.message_hashes
            if len(pks) != len(message_hashes):
                raise Exception("Invalid aggregation info")

            for i in range(len(pks)):
                divisor = divisor_sig.aggregation_info.tree[
                        (message_hashes[i], pks[i])]
                try:
                    dividend = self.aggregation_info.tree[
                        (message_hashes[i], pks[i])]
                except KeyError:
                    raise Exception("Signature is not a subset")
                if i == 0:
                    quotient = (Fq(default_ec.n, dividend)
                                / Fq(default_ec.n, divisor))
                else:
                    # Makes sure the quotient is identical for each public
                    # key, which means message/pk pair is unique.
                    new_quotient = (Fq(default_ec.n, dividend)
                                    / Fq(default_ec.n, divisor))
                    if quotient != new_quotient:
                        raise Exception("Cannot divide by aggregate signature,"
                                        + "msg/pk pairs are not unique")
                message_hashes_to_remove.append(message_hashes[i])
                pubkeys_to_remove.append(pks[i])
            prod += (divisor_sig.value * -quotient)
        copy = Signature(deepcopy(self.value + prod),
                         deepcopy(self.aggregation_info))

        for i in range(len(message_hashes_to_remove)):
            a = message_hashes_to_remove[i]
            b = pubkeys_to_remove[i]
            if (a, b) in copy.aggregation_info.tree:
                del copy.aggregation_info.tree[(a, b)]
        sorted_keys = list(copy.aggregation_info.tree.keys())
        sorted_keys.sort()
        copy.aggregation_info.message_hashes = [t[0] for t in sorted_keys]
        copy.aggregation_info.public_keys = [t[1] for t in sorted_keys]
        return copy

    def set_aggregation_info(self, aggregation_info):
        self.aggregation_info = aggregation_info

    def get_aggregation_info(self):
        return self.aggregation_info

    def __eq__(self, other):
        return self.value.serialize() == other.value.serialize()

    def __hash__(self):
        return int.from_bytes(self.value.serialize(), "big")

    def __lt__(self, other):
        return self.value.serialize() < other.value.serialize()

    def serialize(self):
        return self.value.serialize()

    def size(self):
        return self.SIGNATURE_SIZE

    def __str__(self):
        return "Signature(" + self.value.to_affine().__str__() + ")"

    def __repr__(self):
        return "Signature(" + self.value.to_affine().__repr__() + ")"

    @staticmethod
    def aggregate_sigs_simple(signatures):
        """
        Aggregate signatures by multiplying them together. This is NOT secure
        against rogue public key attacks, so do not use this for signatures
        on the same message.
        """
        q = default_ec.q
        agg_sig = (AffinePoint(Fq2.zero(q), Fq2.zero(q), True, default_ec)
                   .to_jacobian())

        for sig in signatures:
            agg_sig += sig.value

        return Signature.from_g2(agg_sig)

    @staticmethod
    def aggregate_sigs_secure(signatures, public_keys, message_hashes):
        """
        Aggregate signatures using the secure method, which calculates
        exponents based on public keys, and raises each signature to an
        exponent before multiplying them together. This is secure against
        rogue public key attack, but is slower than simple aggregation.
        """
        if (len(signatures) != len(public_keys) or
                len(public_keys) != len(message_hashes)):
            raise Exception("Invalid number of keys")
        mh_pub_sigs = [(message_hashes[i], public_keys[i], signatures[i])
                       for i in range(len(signatures))]

        # Sort by message hash + pk
        mh_pub_sigs.sort()

        computed_Ts = BLS.hash_pks(len(public_keys), public_keys)

        # Raise each sig to a power of each t,
        # and multiply all together into agg_sig
        ec = public_keys[0].ec
        agg_sig = JacobianPoint(Fq2.one(ec.q), Fq2.one(ec.q),
                                Fq2.zero(ec.q), True, ec)

        for i, (_, _, signature) in enumerate(mh_pub_sigs):
            agg_sig += signature * computed_Ts[i]

        return Signature.from_g2(agg_sig)

    @staticmethod
    def aggregate(signatures):
        """
        Aggregates many (aggregate) signatures, using a combination of simple
        and secure aggregation. Signatures are grouped based on which ones
        share common messages, and these are all merged securely.
        """
        public_keys = []  # List of lists
        message_hashes = []  # List of lists

        for signature in signatures:
            if signature.aggregation_info.empty():
                raise Exception("Each signature must have a valid aggregation "
                                + "info")
            public_keys.append(signature.aggregation_info.public_keys)
            message_hashes.append(signature.aggregation_info.message_hashes)

        # Find colliding vectors, save colliding messages
        messages_set = set()
        colliding_messages_set = set()

        for msg_vector in message_hashes:
            messages_set_local = set()
            for msg in msg_vector:
                if msg in messages_set and msg not in messages_set_local:
                    colliding_messages_set.add(msg)
                messages_set.add(msg)
                messages_set_local.add(msg)

        if len(colliding_messages_set) == 0:
            # There are no colliding messages between the groups, so we
            # will just aggregate them all simply. Note that we assume
            # that every group is a valid aggregate signature. If an invalid
            # or insecure signature is given, and invalid signature will
            # be created. We don't verify for performance reasons.
            final_sig = Signature.aggregate_sigs_simple(signatures)
            aggregation_infos = [sig.aggregation_info for sig in signatures]
            final_agg_info = AggregationInfo.merge_infos(aggregation_infos)
            final_sig.set_aggregation_info(final_agg_info)
            return final_sig

        # There are groups that share messages, therefore we need
        # to use a secure form of aggregation. First we find which
        # groups collide, and securely aggregate these. Then, we
        # use simple aggregation at the end.
        colliding_sigs = []
        non_colliding_sigs = []
        colliding_message_hashes = []  # List of lists
        colliding_public_keys = []  # List of lists

        for i in range(len(signatures)):
            group_collides = False
            for msg in message_hashes[i]:
                if msg in colliding_messages_set:
                    group_collides = True
                    colliding_sigs.append(signatures[i])
                    colliding_message_hashes.append(message_hashes[i])
                    colliding_public_keys.append(public_keys[i])
                    break
            if not group_collides:
                non_colliding_sigs.append(signatures[i])

        # Arrange all signatures, sorted by their aggregation info
        colliding_sigs.sort(key=lambda s: s.aggregation_info)

        # Arrange all public keys in sorted order, by (m, pk)
        sort_keys_sorted = []
        for i in range(len(colliding_public_keys)):
            for j in range(len(colliding_public_keys[i])):
                sort_keys_sorted.append((colliding_message_hashes[i][j],
                                         colliding_public_keys[i][j]))
        sort_keys_sorted.sort()
        sorted_public_keys = [pk for (mh, pk) in sort_keys_sorted]

        computed_Ts = BLS.hash_pks(len(colliding_sigs), sorted_public_keys)

        # Raise each sig to a power of each t,
        # and multiply all together into agg_sig
        ec = sorted_public_keys[0].value.ec
        agg_sig = JacobianPoint(Fq2.one(ec.q), Fq2.one(ec.q),
                                Fq2.zero(ec.q), True, ec)

        for i, signature in enumerate(colliding_sigs):
            agg_sig += signature.value * computed_Ts[i]

        for signature in non_colliding_sigs:
            agg_sig += signature.value

        final_sig = Signature.from_g2(agg_sig)
        aggregation_infos = [sig.aggregation_info for sig in signatures]
        final_agg_info = AggregationInfo.merge_infos(aggregation_infos)
        final_sig.set_aggregation_info(final_agg_info)

        return final_sig

    def verify(self):
        """
        This implementation of verify has several steps. First, it
        reorganizes the pubkeys and messages into groups, where
        each group corresponds to a message. Then, it checks if the
        siganture has info on how it was aggregated. If so, we
        exponentiate each pk based on the exponent in the AggregationInfo.
        If not, we find public keys that share messages with others,
        and aggregate all of these securely (with exponents.).
        Finally, since each public key now corresponds to a unique
        message (since we grouped them), we can verify using the
        distinct verification procedure.
        """
        message_hashes = self.aggregation_info.message_hashes
        public_keys = self.aggregation_info.public_keys
        assert(len(message_hashes) == len(public_keys))

        hash_to_public_keys = {}
        for i in range(len(message_hashes)):
            if message_hashes[i] in hash_to_public_keys:
                hash_to_public_keys[message_hashes[i]].append(public_keys[i])
            else:
                hash_to_public_keys[message_hashes[i]] = [public_keys[i]]

        final_message_hashes = []
        final_public_keys = []
        ec = public_keys[0].value.ec
        for message_hash, mapped_keys in hash_to_public_keys.items():
            dedup = list(set(mapped_keys))
            public_key_sum = JacobianPoint(Fq.one(ec.q), Fq.one(ec.q),
                                           Fq.zero(ec.q), True, ec)
            for public_key in dedup:
                try:
                    exponent = self.aggregation_info.tree[(message_hash,
                                                           public_key)]
                    public_key_sum += (public_key.value * exponent)
                except KeyError:
                    return False
            final_message_hashes.append(message_hash)
            final_public_keys.append(public_key_sum.to_affine())

        mapped_hashes = [hash_to_point_prehashed_Fq2(mh)
                         for mh in final_message_hashes]

        g1 = Fq(default_ec.n, -1) * generator_Fq()
        Ps = [g1] + final_public_keys
        Qs = [self.value.to_affine()] + mapped_hashes
        res = ate_pairing_multi(Ps, Qs, default_ec)
        return res == Fq12.one(default_ec.q)


class PrependSignature:
    SIGNATURE_SIZE = 96

    def __init__(self, value):
        self.value = value

    @staticmethod
    def from_bytes(buffer):
        use_big_y = buffer[0] & 0x80
        prepend = buffer[0] & 0x40
        if not prepend:
            raise Exception("Should have prepend bit set")

        buffer = bytes([buffer[0] & 0x1f]) + buffer[1:]

        x0 = int.from_bytes(buffer[:48], "big")
        x1 = int.from_bytes(buffer[48:], "big")
        x = Fq2(default_ec.q, Fq(default_ec.q, x0), Fq(default_ec.q, x1))
        ys = y_for_x(x, default_ec_twist, Fq2)
        y = ys[0]
        if ((use_big_y and ys[1][1] > default_ec.q // 2) or
                (not use_big_y and ys[1][1] < default_ec.q // 2)):
            y = ys[1]

        return PrependSignature(AffinePoint(x, y, False, default_ec_twist)
                                .to_jacobian())

    @staticmethod
    def from_g2(g2_el):
        return PrependSignature(g2_el)

    def __eq__(self, other):
        return self.value.serialize() == other.value.serialize()

    def __hash__(self):
        return int.from_bytes(self.value.serialize(), "big")

    def __lt__(self, other):
        return self.value.serialize() < other.value.serialize()

    def serialize(self):
        ret = bytearray(self.value.serialize())
        ret[0] |= 0x40
        return bytes(ret)

    def size(self):
        return self.SIGNATURE_SIZE

    def __str__(self):
        return "PrependSignature(" + self.value.to_affine().__str__() + ")"

    def __repr__(self):
        return "PrependSignature(" + self.value.to_affine().__repr__() + ")"

    @staticmethod
    def aggregate(signatures):
        """
        Aggregate signatures by multiplying them together. This IS secure
        against rogue public key attacks, assuming these signatures were
        generated using sign_prepend.
        """
        q = default_ec.q
        agg_sig = (AffinePoint(Fq2.zero(q), Fq2.zero(q), True, default_ec)
                   .to_jacobian())

        for sig in signatures:
            agg_sig += sig.value

        return PrependSignature.from_g2(agg_sig)

    def verify(self, message_hashes, public_keys):
        """
        Verifies messages using the prepend method. It prepends public keys
        to message hashes before verifying.
        """
        assert(len(message_hashes) == len(public_keys))
        mapped_hashes = [hash_to_point_prehashed_Fq2(hash256(public_keys[i].serialize() + message_hashes[i]))
                         for i in range(len(message_hashes))]
        keys = [pk.value.to_affine() for pk in public_keys]

        g1 = Fq(default_ec.n, -1) * generator_Fq()
        Ps = [g1] + keys
        Qs = [self.value.to_affine()] + mapped_hashes
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
