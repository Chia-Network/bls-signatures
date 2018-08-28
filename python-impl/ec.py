from collections import namedtuple
from fields import Fq, Fq2, Fq6, Fq12, FieldExtBase
import bls12381
import random
from util import hash256

# Struct for elliptic curve parameters
EC = namedtuple("EC", "q a b gx gy g2x g2y n h x k")

# use secp256k1 as default
default_ec = EC(*bls12381.parameters())
default_ec_twist = EC(*bls12381.parameters_twist())


class AffinePoint:
    def __init__(self, x, y, infinity, ec=default_ec):
        if (not isinstance(x, Fq) and not isinstance(x, FieldExtBase) or
           (not isinstance(y, Fq) and not isinstance(y, FieldExtBase)) or
           type(x) != type(y)):
            raise "x,y should be field elements"
        self.FE = type(x)
        self.x = x
        self.y = y
        self.infinity = infinity
        self.ec = ec

    def is_on_curve(self):
        if self.infinity:
            return True
        left = self.y * self.y
        right = self.x * self.x * self.x + self.ec.a * self.x + self.ec.b

        return left == right

    def __add__(self, other):
        if other == 0:
            return self
        if not isinstance(other, AffinePoint):
            raise "Incorrect object"

        return add_points(self, other, self.ec, self.FE)

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        return self.__add__(other.negate())

    def __rsub__(self, other):
        return self.negate().__add__(other)

    def __str__(self):
        return ("AffinePoint(x=" + self.x.__str__() +
                ", y=" + self.y.__str__() +
                ", i=" + str(self.infinity) + ")\n")

    def __repr__(self):
        return ("AffinePoint(x=" + self.x.__repr__() +
                ", y=" + self.y.__repr__() +
                ", i=" + str(self.infinity) + ")\n")

    def __eq__(self, other):
        if not isinstance(other, AffinePoint):
            return False
        return (self.x == other.x and
                self.y == other.y and
                self.infinity == other.infinity)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __mul__(self, c):
        if not isinstance(c, self.FE) and not isinstance(c, int):
            raise ValueError("Error, must be int or FE")
        if isinstance(c, int):
            c = Fq(self.ec.n, c)
        return scalar_mult_jacobian(c, self.to_jacobian(), self.ec).to_affine()

    def negate(self):
        return AffinePoint(self.x, -self.y, self.infinity, self.ec)

    def __rmul__(self, c):
        return self.__mul__(c)

    def to_jacobian(self):
        return JacobianPoint(self.x, self.y, self.FE.one(self.ec.q),
                             self.infinity, self.ec)

    def serialize(self):
        return str(self.x) + str(self.y) + str(self.infinity)


class JacobianPoint:
    def __init__(self, x, y, z, infinity, ec=default_ec):
        if (not isinstance(x, Fq) and not isinstance(x, FieldExtBase) or
           (not isinstance(y, Fq) and not isinstance(y, FieldExtBase)) or
           (not isinstance(z, Fq) and not isinstance(z, FieldExtBase))):
            raise "x,y should be field elements"
        self.FE = type(x)
        self.x = x
        self.y = y
        self.z = z
        self.infinity = infinity
        self.ec = ec

    def is_on_curve(self):
        if self.infinity:
            return True
        return self.to_affine().is_on_curve()

    def __add__(self, other):
        if other == 0:
            return self
        if not isinstance(other, JacobianPoint):
            raise ValueError("Incorrect object")

        return add_points_jacobian(self, other, self.ec, self.FE)

    def __radd__(self, other):
        return self.__add__(other)

    def __str__(self):
        return ("JacobianPoint(x=" + self.x.__str__() +
                ", y=" + self.y.__str__() +
                "z=" + self.z.__str__() +
                ", i=" + str(self.infinity) + ")\n")

    def __eq__(self, other):
        if not isinstance(other, JacobianPoint):
            return False
        return self.to_affine() == other.to_affine()

    def __ne__(self, other):
        return not self.__eq__(other)

    def __mul__(self, c):
        if not isinstance(c, int):
            raise ValueError("Error, must be int or Fq")
        if not isinstance(c, Fq):
            c = Fq(self.ec.n, c)
        return scalar_mult_jacobian(c, self, self.ec)

    def __rmul__(self, c):
        return self.__mul__(c)

    def to_affine(self):
        if self.infinity:
            return AffinePoint(0, 0, self.infinity, self.ec)
        new_x = self.x / pow(self.z, 2)
        new_y = self.y / pow(self.z, 3)
        return AffinePoint(new_x, new_y, self.infinity, self.ec)

    def serialize(self):
        return self.to_affine().serialize()


def y_for_x(x, ec=default_ec, FE=Fq):
    if not isinstance(x, FE):
        x = FE(ec.q, x)

    u = x * x * x + ec.a * x + ec.b

    y = u.modsqrt()
    if y == 0 or not AffinePoint(x, y, False, ec).is_on_curve():
        raise ValueError("No y for point x")
    return sorted([y, ec.q - y])


def double_point(p1, ec=default_ec, FE=Fq):
    x, y = p1.x, p1.y
    left = 3 * x * x
    left = left + ec.a
    s = left / (2 * y)
    new_x = s * s - x - x
    new_y = s * (x - new_x) - y
    return AffinePoint(new_x, new_y, False, ec)


def add_points(p1, p2, ec=default_ec, FE=Fq):
    assert(p1.is_on_curve())
    assert(p2.is_on_curve())
    if p1.infinity:
        return p2
    if p2.infinity:
        return p1
    if p1 == p2:
        return double_point(p1, ec, FE)
    if p1.x == p2.x:
        return AffinePoint(0, 0, True, ec)

    x1, y1 = p1.x, p1.y
    x2, y2 = p2.x, p2.y
    s = (y2 - y1) / (x2 - x1)
    new_x = s * s - x1 - x2
    new_y = s * (x1 - new_x) - y1
    return AffinePoint(new_x, new_y, False, ec)


def double_point_jacobian(p1, ec=default_ec, FE=Fq):
    X, Y, Z = p1.x, p1.y, p1.z
    if Y == FE.zero(ec.q) or p1.infinity:
        return JacobianPoint(FE.one(ec.q), FE.one(ec.q),
                             FE.zero(ec.q), True, ec)

    # S = 4*X*Y^2
    S = 4 * X * Y * Y

    Z_sq = Z * Z
    Z_4th = Z_sq * Z_sq
    Y_sq = Y * Y
    Y_4th = Y_sq * Y_sq

    # M = 3*X^2 + a*Z^4
    M = 3 * X * X
    M += ec.a * Z_4th

    # X' = M^2 - 2*S
    X_p = M * M - 2 * S
    # Y' = M*(S - X') - 8*Y^4
    Y_p = M * (S - X_p) - 8 * Y_4th
    # Z' = 2*Y*Z
    Z_p = 2 * Y * Z
    return JacobianPoint(X_p, Y_p, Z_p, False, ec)


def add_points_jacobian(p1, p2, ec=default_ec, FE=Fq):
    if p1.infinity:
        return p2
    if p2.infinity:
        return p1
    # U1 = X1*Z2^2
    U1 = p1.x * pow(p2.z, 2)
    # U2 = X2*Z1^2
    U2 = p2.x * pow(p1.z, 2)
    # S1 = Y1*Z2^3
    S1 = p1.y * pow(p2.z, 3)
    # S2 = Y2*Z1^3
    S2 = p2.y * pow(p1.z, 3)
    if U1 == U2:
        if S1 != S2:
            return JacobianPoint(FE.one(ec.q), FE.one(ec.q),
                                 FE.zero(ec.q), True, ec)
        else:
            return double_point_jacobian(p1, ec, FE)

    # H = U2 - U1
    H = U2 - U1
    # R = S2 - S1
    R = S2 - S1
    H_sq = H * H
    H_cu = H * H_sq
    # X3 = R^2 - H^3 - 2*U1*H^2
    X3 = R * R - H_cu - 2 * U1 * H_sq
    # Y3 = R*(U1*H^2 - X3) - S1*H^3
    Y3 = R * (U1 * H_sq - X3) - S1 * H_cu
    # Z3 = H*Z1*Z2
    Z3 = H * p1.z * p2.z
    return JacobianPoint(X3, Y3, Z3, False, ec)


# Double and add
def scalar_mult(c, p1, ec=default_ec, FE=Fq):
    if p1.infinity or c % ec.q == 0:
        return AffinePoint(FE.zero(ec.q), FE.zero(ec.q), ec)
    if c < 0 or c > ec.n:
        c = c % ec.n
    result = AffinePoint(FE.zero(ec.q), FE.zero(ec.q), True, ec)
    addend = p1
    while c > 0:
        if c & 1:
            result += addend

        # double point
        addend += addend
        c = c >> 1

    return result


def scalar_mult_jacobian(c, p1, ec=default_ec, FE=Fq):
    if p1.infinity or c % ec.q == 0:
        return JacobianPoint(FE.one(ec.q), FE.one(ec.q),
                             FE.zero(ec.q), True, ec)
    if isinstance(c, FE):
        c = int(c)
    if c < 0 or c > ec.n:
        c = c % ec.n
    result = JacobianPoint(FE.one(ec.q), FE.one(ec.q),
                           FE.zero(ec.q), True, ec)
    addend = p1
    while c > 0:
        if c & 1:
            result += addend
        # double point
        addend += addend
        c = c >> 1
    return result


def order(ec=default_ec):
    return ec.n


def rand_scalar(ec=default_ec):
    return random.randrange(1, ec.n)


def rand_field_element(ec=default_ec):
    return Fq(ec.q, random.randrange(1, ec.q))


def generator_Fq(ec=default_ec):
    return AffinePoint(ec.gx, ec.gy, False, ec)


def generator_Fq2(ec=default_ec_twist):
    return AffinePoint(ec.g2x, ec.g2y, False, ec)


def untwist(point, ec=default_ec):
    """
    Given a point on G2 on the twisted curve, this converts it's
    coordinates back from Fq2 to Fq12.
    """
    f = Fq12.one(ec.q)
    wsq = Fq12(ec.q, f.root, Fq6.zero(ec.q))
    wcu = Fq12(ec.q, Fq6.zero(ec.q), f.root)
    return AffinePoint(point.x / wsq, point.y / wcu, False, ec)


def twist(point, ec=default_ec_twist):
    """
    Given an untwisted point, this converts it's
    coordinates to a point on the twisted curve.
    """
    f = Fq12.one(ec.q)
    wsq = Fq12(ec.q, f.root, Fq6.zero(ec.q))
    wcu = Fq12(ec.q, Fq6.zero(ec.q), f.root)
    new_x = (point.x * wsq)
    new_y = (point.y * wcu)
    return AffinePoint(new_x, new_y, False, ec)


def psi(P, ec=default_ec):
    ut = untwist(P, ec)
    t = AffinePoint(pow(ut.x, ec.q), pow(ut.y, ec.q), False, ec)
    t2 = twist(t, ec)
    return AffinePoint(t2.x[0][0], t2.y[0][0], False, ec)


def hash_to_point_Fq(m, ec=default_ec):
    """
    Try and add algorithm. Keep incrementing x until there
    is a valid y value for it.
    """
    h = hash256(m)
    x = Fq(ec.q, int.from_bytes(h, 'big'))
    ys = []
    while True:
        try:
            ys = y_for_x(x, ec)
        except ValueError:
            x = x + 1
            continue
            # Try again
        return ec.h * AffinePoint(Fq(ec.q, x), ys[0], False, ec)


def hash_to_point_prehashed_Fq2(h, ec=default_ec_twist):
    """
    Try and add algorithm. Keep incrementing x until there
    is a valid y value for it. After that, multiply by the
    cofactor of G2 in order to send the point to the r-torsion.
    """
    x = Fq2(ec.q, Fq(ec.q, int.from_bytes(h, 'big')), Fq.zero(ec.q))
    ys = []
    while True:
        try:
            ys = y_for_x(x, ec, Fq2)
        except ValueError:
            x = x + 1
            continue
            # Try again
        P = AffinePoint(x, ys[0], False, ec)
        x = -ec.x

        # This is the cofactor multiplication, done in a more
        # efficient way. See page 11 of "Efficient hash maps
        # to G2 on BLS curves" by Budrioni and Pintore.
        psi2P = psi(psi(2*P, ec), ec)
        t0 = x*P
        t1 = x*t0

        t3 = psi((x+1) * P, ec)
        t2 = (t1 + t0) - P
        return t2 - t3 + psi2P


def hash_to_point_Fq2(m, ec=default_ec_twist):
    h = hash256(m)
    return hash_to_point_prehashed_Fq2(h, ec)


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
