from ec import (AffinePoint, default_ec, default_ec_twist,
                generator_Fq, generator_Fq2, hash_to_point_Fq)
from fields import Fq
from secrets import SystemRandom
from typing import List
RNG = SystemRandom()


def lagrange_coefficients(X: List[int], ec=default_ec) -> List[Fq]:
    """
    We have k+1 integers X[i], all different mod ec.n and non-zero.
    The points (X[i], P(X[i])) interpolate into P(X), a degree k polynomial.

    Returns coefficients L_i such that P(0) = sum L_i * P(X[i]).
    """
    N = len(X)

    # Check all x values are different and non-zero.
    assert len(set(X)) == N and all(x != 0 for x in X)

    def weight(j):
        ans = Fq(ec.n, 1)
        for i in range(N):
            if i != j:
                ans *= Fq(ec.n, X[j] - X[i])
        return ~ans

    # Using the second barycentric form,
    # P(0) = (sum_j (y_j * w_j / x_j)) / (sum_j w_j/x_j)
    # If desired, the weights can be precomputed.

    ans = []
    denominator = Fq(ec.n, 0)
    for j in range(N):
        shift = weight(j) * ~Fq(ec.n, -X[j])
        ans.append(shift)
        denominator += shift
    denominator = ~denominator
    for i in range(len(ans)):
        ans[i] *= denominator
    return ans


def lagrange_at_zero(X: List[int], Y: List[Fq], ec=default_ec) -> Fq:
    """
    The k+1 points (X[i], Y[i]) interpolate into P(X),
    a degree k polynomial.

    Returns P(0).
    """
    ans = Fq(ec.n, 0)
    for lamb, y in zip(lagrange_coefficients(X, ec), Y):
        ans += lamb * y
    return ans


def signature_share(secret_share: Fq, X: List[int], P: int,
                    message: str, ec=default_ec):
    """
    As player P out of all players X contributing a share,
    return a signature share for the message with respect to X.
    """
    assert P in X
    i = X.index(P)
    h = hash_to_point_Fq(message)
    lambs = lagrange_coefficients(X, ec)
    return h * (lambs[i] * secret_share)


def create_secret_shares(N: int, T: int, ec=default_ec,
                         ec_twist=default_ec_twist):
    """
    Choose a polynomial with random non-zero coefficients in F_{ec.n}.
    Return:
      - commitments to that polynomial,
      - shares poly(j) to be sent to player j
      - poly(0), your share of the master secret key
    """
    g2 = generator_Fq2(ec_twist)
    poly = [Fq(ec.n, RNG.randint(1, ec.n - 1)) for _ in range(T+1)]
    commitments = [g2 * c for c in poly]
    secret_shares = [sum(c * pow(x, i, ec.n) for i, c in enumerate(poly))
                     for x in range(1, N+1)]
    return commitments, secret_shares, poly[0]


def verify_secret_shares(N: int, T: int, P: int, shares: List[Fq],
                         commitments: List[List[AffinePoint]],
                         ec=default_ec,
                         ec_twist=default_ec_twist) -> List[bool]:
    """
    Player i+1 has given you (P) your secret share, shares[i] = f_{i+1}(P)
    and has also commited to polynomial f_{i+1} via commitments[i].

    Return a list of results, the i-th result is True if the share from
    player i+1 is correct.
    """
    assert len(shares) == len(commitments) == N
    assert all(len(cpoly) == T+1 for cpoly in commitments)
    g2 = generator_Fq2(ec_twist)

    results = []
    for j in range(N):
        cpoly = commitments[j]
        lhs = g2 * shares[j]
        rhs = cpoly[0]
        for k in range(1, len(cpoly)):
            rhs += cpoly[k] * pow(P, k, ec.n)
        results.append(lhs == rhs)

    return results


def test():
    from itertools import combinations
    ec = default_ec
    g = generator_Fq(ec)

    # create shares
    T, N = 2, 5
    commitments = []
    shares = [[None] * N for _ in range(N)]
    secrets = []
    for i in range(N):
        commi, share, secret = create_secret_shares(N, T)
        for j, s in enumerate(share):
            shares[j][i] = s
        commitments.append(commi)
        secrets.append(secret)

    # verify shares
    for P in range(1, N+1):
        results = verify_secret_shares(N, T, P,
                                       shares[P-1], commitments)
        assert all(results)

    # master_fn_at[i] = F(i+1), where F = sum f_j
    master_fn_at = [sum(share) for share in shares]
    pubkey = sum(c[0] for c in commitments)
    secretkey = sum(secrets)
    msg = 'Test'
    h = hash_to_point_Fq(msg, ec)

    # check lagrange
    for X in combinations(range(1, N+1), T+1):
        # X: a list of T indices like [1, 2, 5]
        secretcand = lagrange_at_zero(X, [master_fn_at[x-1] for x in X])
        assert secretcand == secretkey

        sigcand = sum(signature_share(master_fn_at[P-1], X, P, msg)
                      for P in X)
        assert sigcand == h * secretkey

test()
