from math import ceil
from util import hash256

BLOCK_SIZE = 32


def hmac(key: bytes, message: bytes) -> bytes:
    k_prime: bytes = key
    if len(key) > BLOCK_SIZE:
        k_prime = hash256(key)
    while len(k_prime) < BLOCK_SIZE:
        k_prime += bytes([0])

    assert len(k_prime) == BLOCK_SIZE

    first = bytes([k_prime[i] ^ 0x5C for i in range(BLOCK_SIZE)])
    second = hash256(bytes([k_prime[i] ^ 0x36 for i in range(BLOCK_SIZE)]) + message)

    return hash256(first + second)


def extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac(salt, ikm)


def expand(L: int, prk: bytes, info: bytes) -> bytes:
    N: int = ceil(L / BLOCK_SIZE)
    bytes_written: int = 0
    okm: bytes = b""

    for i in range(1, N + 1):
        if i == 1:
            T: bytes = hmac(info + bytes([1]), prk)
        else:
            T = hmac(T + info + bytes([i]), prk)
        to_write = L - bytes_written
        if to_write > BLOCK_SIZE:
            to_write = BLOCK_SIZE
        okm += T[:to_write]
        bytes_written += to_write
    assert bytes_written == L
    return okm


def extract_expand(key: bytes, salt: bytes, info: bytes) -> bytes:
    return bytes()
    # return expand(prk, info)
