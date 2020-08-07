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


def extract_expand(L: int, key: bytes, salt: bytes, info: bytes) -> bytes:
    prk = extract(salt, key)
    return expand(L, prk, info)


"""
Copyright 2020 Chia Network Inc

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
