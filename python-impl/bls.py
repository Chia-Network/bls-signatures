from ec import (generator_Fq, hash_to_point_Fq2, default_ec,
                hash_to_point_prehashed_Fq2, y_for_x,
                AffinePoint, JacobianPoint)
from fields import Fq, Fq2, Fq12
from util import hmac256, hash256
from pairing import ate_pairing_multi


class BLSPublicKey:
    """
    Public keys are G1 elements, which are elliptic curve points (x, y), where
    each x, y is a 381 bit Fq element. The serialized represenentation is just
    the x value, and thus 48 bytes. (With the 1st bit determining the valid y).
    """
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
        return self.value.serialize()

    def __lt__(self, other):
        return self.value.serialize() < other.value.serialize()

    def __str__(self):
        return "BLSPublicKey(" + self.value.to_affine().__str__() + ")"

    def __repr__(self):
        return "BLSPublicKey(" + self.value.to_affine().__repr__() + ")"


class BLSPrivateKey:
    """
    Private keys are just random integers between 1 and the group order.
    """
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
        aggregation_info = AggregationInfo.from_msg(self.get_public_key(), m)
        return BLSSignature.from_g2(self.value * r, aggregation_info)

    def sign_prehashed(self, h):
        r = hash_to_point_prehashed_Fq2(h).to_jacobian()
        aggregation_info = AggregationInfo.from_msg_hash(self.get_public_key(),
                                                         h)
        return BLSSignature.from_g2(self.value * r, aggregation_info)

    def __lt__(self, other):
        return self.value.serialize() < other.value.serialize()

    def serialize(self):
        return self.value.to_bytes(self.PRIVATE_KEY_SIZE, "big")

    def __str__(self):
        return "BLSPrivateKey(" + self.value.__str__() + ")"

    def __repr__(self):
        return "BLSPrivateKey(" + self.value.__repr__() + ")"


class ExtendedPrivateKey:
    version = 1

    def __init__(self, version, depth, parent_fingerprint,
                 child_number, chain_code, sk):
        self.version = version
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.child_number = child_number
        self.chain_code = chain_code
        self.sk = sk

    def from_seed(seed):
        prefix = [66, 76, 83, 32, 72, 68, 32, 115, 101, 101, 100]
        i_left = hmac256(bytes([0]) + seed, prefix)
        i_right = hmac256(bytes([1]) + seed, prefix)

        sk_int = int.from_bytes(i_left, "big") % default_ec.n
        sk = BLSPrivateKey.from_bytes(
            sk_int.to_bytes(BLSPrivateKey.PRIVATE_KEY_SIZE, "big"))
        return ExtendedPrivateKey(ExtendedPrivateKey.version, 0, 0,
                                  0, i_right, i_left, sk)


class AggregationInfo:
    """
    AggregationInfo represents information of how a tree of aggregate
    signatures was created. Different tress will result in different
    signatures, due to exponentiations required for security.

    An AggregationInfo is represented as a map from (message_hash, pk)
    to exponents. When verifying, a verifier will take the signature,
    along with this map, and raise each public key to the correct
    exponent, and multiply the pks together, for identical messages.
    """
    def __init__(self, tree, message_hashes, public_keys):
        self.tree = tree
        self.message_hashes = message_hashes
        self.public_keys = public_keys

    def empty(self):
        return not self.tree

    def __lt__(self, other):
        """
        Compares two AggregationInfo objects, this is necessary for sorting
        them. Comparison is done by comparing (message hash, pk, exponent)
        """
        combined = [(self.message_hashes[i], self.public_keys[i],
                     self.tree[(self.message_hashes[i], self.public_keys[i])])
                    for i in range(len(self.public_keys))]
        combined_other = [(other.message_hashes[i], other.public_keys[i],
                           other.tree[(other.message_hashes[i],
                                       other.public_keys[i])])
                          for i in range(len(other.public_keys))]

        for i in range(len(combined)):
            if i >= len(combined_other):
                return False
            if combined[i] < combined_other[i]:
                return True
            if combined_other[i] < combined[i]:
                return False
        return True

    @staticmethod
    def from_msg_hash(public_key, message_hash):
        tree = {}
        tree[(message_hash, public_key)] = 1
        return AggregationInfo(tree, [message_hash], [public_key])

    @staticmethod
    def from_msg(pk, message):
        return AggregationInfo.from_msg_hash(pk, hash256(message))

    @staticmethod
    def simple_merge_infos(aggregation_infos):
        """
        Infos are just merged together with no addition of exponents,
        since they are disjoint
        """
        new_tree = {}
        for info in aggregation_infos:
            new_tree.update(info.tree)
        mh_pubkeys = [k for k, v in new_tree.items()]

        mh_pubkeys.sort()

        message_hashes = [message_hash for (message_hash, public_key)
                          in mh_pubkeys]
        public_keys = [public_key for (message_hash, public_key)
                       in mh_pubkeys]

        return AggregationInfo(new_tree, message_hashes, public_keys)

    @staticmethod
    def secure_merge_infos(colliding_infos):
        """
        Infos are merged together with combination of exponents
        """

        # Groups are sorted by message then pk then exponent
        # Each info object (and all of it's exponents) will be
        # exponentiated by one of the Ts
        colliding_infos.sort()

        sorted_keys = []
        for info in colliding_infos:
            for key, value in info.tree.items():
                sorted_keys.append(key)
        sorted_keys.sort()
        sorted_pks = [public_key for (message_hash, public_key)
                      in sorted_keys]
        computed_Ts = BLS.hash_pks(len(colliding_infos), sorted_pks)

        # Group order, exponents can be reduced mod the order
        order = sorted_pks[0].value.ec.n

        new_tree = {}
        for i in range(len(colliding_infos)):
            for key, value in colliding_infos[i].tree.items():
                if key not in new_tree:
                    # This message & pk have not been included yet
                    new_tree[key] = (value * computed_Ts[i]) % order
                else:
                    # This message and pk are already included, so multiply
                    addend = value * computed_Ts[i]
                    new_tree[key] = (new_tree[key] + addend) % order
        mh_pubkeys = [k for k, v in new_tree.items()]
        mh_pubkeys.sort()
        message_hashes = [message_hash for (message_hash, public_key)
                          in mh_pubkeys]
        public_keys = [public_key for (message_hash, public_key)
                       in mh_pubkeys]
        return AggregationInfo(new_tree, message_hashes, public_keys)

    @staticmethod
    def merge_infos(aggregation_infos):
        messages = set()
        colliding_messages = set()
        for info in aggregation_infos:
            messages_local = set()
            for key, value in info.tree.items():
                if key[0] in messages and key[0] not in messages_local:
                    colliding_messages.add(key[0])
                messages.add(key[0])
                messages_local.add(key[0])

        if len(colliding_messages) == 0:
            return AggregationInfo.simple_merge_infos(aggregation_infos)

        colliding_infos = []
        non_colliding_infos = []
        for info in aggregation_infos:
            info_collides = False
            for key, value in info.tree.items():
                if key[0] in colliding_messages:
                    info_collides = True
                    colliding_infos.append(info)
                    break
            if not info_collides:
                non_colliding_infos.append(info)

        combined = AggregationInfo.secure_merge_infos(colliding_infos)
        non_colliding_infos.append(combined)
        return AggregationInfo.simple_merge_infos(non_colliding_infos)


class BLSSignature:
    """
    Signatures are G1 elements, which are elliptic curve points (x, y), where
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
        x0 = int.from_bytes(buffer[:48], "big")
        x1 = int.from_bytes(buffer[48:], "big")
        x = Fq2(default_ec.q, Fq(default_ec.q, x0), Fq(default_ec.q, x1))
        y = y_for_x(x)
        return BLSSignature(AffinePoint(x, y, False, default_ec).to_jacobian(),
                            aggregation_info)

    @staticmethod
    def from_g2(g2_el, aggregation_info=None):
        return BLSSignature(g2_el, aggregation_info)

    def set_aggregation_info(self, aggregation_info):
        self.aggregation_info = aggregation_info

    def __lt__(self, other):
        return self.value.serialize() < other.value.serialize()

    def serialize(self):
        return self.value.serialize()

    def __str__(self):
        return "BLSSignature(" + self.value.to_affine().__str__() + ")"

    def __repr__(self):
        return "BLSSignature(" + self.value.to_affine().__repr__() + ")"


class BLS:
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

        return BLSSignature.from_g2(agg_sig)

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
            raise "Invalid number of keys"
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

        return BLSSignature.from_g2(agg_sig)

    @staticmethod
    def aggregate_sigs(signatures):
        """
        Aggregates many (aggregate) signatures, using a combination of simple
        and secure aggregation. Signatures are grouped based on which ones
        share common messages, and these are all merged securely.
        """
        public_keys = []  # List of lists
        message_hashes = []  # List of lists

        for signature in signatures:
            if signature.aggregation_info.empty():
                raise "Each signature must have a valid aggregation info"
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
            final_sig = BLS.aggregate_sigs_simple(signatures)
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

        computed_Ts = BLS.hash_pks(len(sorted_public_keys), sorted_public_keys)

        # Raise each sig to a power of each t,
        # and multiply all together into agg_sig
        ec = sorted_public_keys[0].value.ec
        agg_sig = JacobianPoint(Fq2.one(ec.q), Fq2.one(ec.q),
                                Fq2.zero(ec.q), True, ec)

        for i, signature in enumerate(colliding_sigs):
            agg_sig += signature.value * computed_Ts[i]

        for signature in non_colliding_sigs:
            agg_sig += signature.value

        final_sig = BLSSignature.from_g2(agg_sig)
        aggregation_infos = [sig.aggregation_info for sig in signatures]
        final_agg_info = AggregationInfo.merge_infos(aggregation_infos)
        final_sig.set_aggregation_info(final_agg_info)

        return final_sig

    @staticmethod
    def verify(signature):
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
        message_hashes = signature.aggregation_info.message_hashes
        public_keys = signature.aggregation_info.public_keys

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
                    exponent = signature.aggregation_info.tree[(message_hash,
                                                                public_key)]
                    public_key_sum += (public_key.value * exponent)
                except KeyError:
                    return False
            final_message_hashes.append(message_hash)
            final_public_keys.append(public_key_sum.to_affine())

        mapped_hashes = [hash_to_point_prehashed_Fq2(mh)
                         for mh in final_message_hashes]

        g1 = -1 * generator_Fq()
        Ps = [g1] + final_public_keys
        Qs = [signature.value.to_affine()] + mapped_hashes
        res = ate_pairing_multi(Ps, Qs, default_ec)
        return res == Fq12.one(default_ec.q)

    @staticmethod
    def aggregate_public_keys(public_keys, secure):
        """
        Aggregates public keys together
        """
        if len(public_keys) < 1:
            raise "Invalid number of keys"
        public_keys.sort()

        computed_Ts = BLS.hash_pks(len(public_keys), public_keys)

        ec = public_keys[0].value.ec
        sum_keys = JacobianPoint(Fq.one(ec.q), Fq.one(ec.q),
                                 Fq.zero(ec.q), True, ec)
        for i in range(len(public_keys)):
            addend = public_keys[i].value
            if secure:
                addend *= computed_Ts[i]
            sum_keys += addend

        return BLSPublicKey.from_g1(sum_keys)

    @staticmethod
    def aggregate_private_keys(private_keys, public_keys, secure):
        """
        Aggregates private keys together
        """
        if secure and len(private_keys) != len(public_keys):
            raise "Invalid number of keys"

        priv_pub_keys = [(public_keys[i], private_keys[i])
                         for i in range(len(private_keys))]
        # Sort by public keys
        priv_pub_keys.sort()

        computed_Ts = BLS.hash_pks(len(private_keys), public_keys)

        n = public_keys[0].value.ec.n
        sum_keys = 0
        for i in range(len(priv_pub_keys)):
            addend = priv_pub_keys[i][1].value
            if (secure):
                addend *= computed_Ts[i]
            sum_keys = (sum_keys + addend) % n

        return BLSPrivateKey.from_bytes(sum_keys.to_bytes(32, "big"))

    @staticmethod
    def hash_pks(num_outputs, public_keys):
        """
        Construction from https://eprint.iacr.org/2018/483.pdf
        Two hashes are performed for speed.
        """
        input_bytes = b''.join([pk.serialize() for pk in public_keys])
        pk_hash = hash256(input_bytes)
        order = public_keys[0].value.ec.n

        computed_Ts = []
        for i in range(num_outputs):
            t = int.from_bytes(hash256(i.to_bytes(4, "big") + pk_hash), "big")
            computed_Ts.append(t % order)

        return computed_Ts


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
