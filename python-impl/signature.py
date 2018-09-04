from ec import default_ec, y_for_x, AffinePoint
from fields import Fq, Fq2


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

