from typing import Sequence, Tuple
import secrets
import nacl.encoding
import nacl.hash
from fe25519 import *
from ge25519 import *

#
# Buffer size constants.
#

def crypto_generichash_bytes():
    return 32

def crypto_secretbox_noncebytes():
    return 24

def crypto_box_secretkeybytes():
    return 32

def crypto_core_ed25519_scalarbytes() -> int:
    return 32

#
# General libsodium primitives.
#

def sodium_is_zero(n: bytes) -> int: # 32-byte input.
    d = 0
    for i in range(len(n)):
        d |= n[i]
    return 1 & ((d - 1) >> 8)

def crypto_generichash(m):
    return nacl.hash.blake2b(bytes(m), encoder=nacl.encoding.RawEncoder)

#
# Ed25519 primitives for elliptic curve operations.
#

sc25519_is_canonical_L = [ # 2^252+27742317777372353535851937790883648493
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
    0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
]

def sc25519_is_canonical(s: bytes) -> int: # 32-byte input.
    c = 0 # unsigned char
    n = 1 # unsigned char
    for i in range(31, -1, -1):
        c |= ((s[i] - sc25519_is_canonical_L[i]) >> 8) & n
        n &= ((s[i] ^ sc25519_is_canonical_L[i]) - 1) >> 8

    return c != 0

def _crypto_scalarmult_ed25519_is_inf(s: bytes) -> int: # 32-byte input.
    c = s[0] ^ 1
    for i in range(1,31):
        c |= s[i]
    c |= s[31] & 127
    return ((c - 1) >> 8) & 1

def crypto_core_ed25519_scalar_random() -> bytes:
    while True:
        r = bytearray(secrets.token_bytes(crypto_core_ed25519_scalarbytes()))
        r[-1] &= 0x1f
        if not sc25519_is_canonical(r) == 0 and not sodium_is_zero(r):
           return r

def _crypto_scalarmult_ed25519_base(n: bytes, clamp: int) -> bytes:
    t = bytearray([b for b in n])
    if clamp != 0:
        t[0] &= 248
        t[31] |= 64

    t[31] &= 127

    q = ge25519_p3.scalar_mult_base(t).to_bytes()
    if _crypto_scalarmult_ed25519_is_inf(q) != 0 or sodium_is_zero(n):
        return None

    return q

def crypto_scalarmult_ed25519_base_noclamp(n: bytes) -> bytes:
    return _crypto_scalarmult_ed25519_base(n, 0)

def _crypto_scalarmult_ed25519(n: bytes, p: bytes, clamp: int) -> bytes:
    P = ge25519_p3.from_bytes(p)
    if ge25519.is_canonical(p) == 0 or ge25519.has_small_order(p) != 0 or\
       P.root_check != 0 or P.is_on_main_subgroup() == 0:
        return None

    t = bytearray([b for b in n])
    if clamp != 0:
        t[0] &= 248
        t[31] |= 64

    t[31] &= 127

    q = P.scalar_mult(t).to_bytes()
    if _crypto_scalarmult_ed25519_is_inf(q) != 0 or sodium_is_zero(n) == 1:
        return None

    return q

def crypto_scalarmult_ed25519_noclamp(n: bytes, p: bytes) -> bytes:
    return _crypto_scalarmult_ed25519(n, p, 0)

def crypto_core_ed25519_add(p: bytes, q: bytes) -> bytes:
    p_p3 = ge25519_p3.from_bytes(p)
    q_p3 = ge25519_p3.from_bytes(q)

    if p_p3.root_check != 0 or p_p3.is_on_curve() == 0 or\
       q_p3.root_check != 0 or q_p3.is_on_curve() == 0:
       return None

    q_cached = ge25519_cached.from_p3(q_p3)
    r_p1p1 = ge25519_p1p1.add(p_p3, q_cached)
    r_p3 = ge25519_p3.from_p1p1(r_p1p1)

    return r_p3.to_bytes()

def crypto_core_ed25519_sub(p: bytes, q: bytes) -> bytes:
    p_p3 = ge25519_p3.from_bytes(p)
    q_p3 = ge25519_p3.from_bytes(q)

    if p_p3.root_check != 0 or p_p3.is_on_curve() == 0 or\
       q_p3.root_check != 0 or q_p3.is_on_curve() == 0:
       return None

    q_cached = ge25519_cached.from_p3(q_p3)
    r_p1p1 = ge25519_p1p1.sub(p_p3, q_cached)
    r_p3 = ge25519_p3.from_p1p1(r_p1p1)

    return r_p3.to_bytes()

#
# Ristretto255 primitives for elliptic curve operations.
#

def ristretto255_is_canonical(s: bytes) -> int: # 32-byte input.
    c = ((s[31] & 0x7f) ^ 0x7f) % 256
    for i in range(30, 0, -1):
        c |= (s[i] ^ 0xff) % 256
    c = (c - 1) >> 8
    d = ((0xed - 1 - s[0]) >> 8) % 256
    return 1 - (((c & d) | s[0]) & 1)

def crypto_core_ristretto255_scalar_random() -> bytes:
    return crypto_core_ed25519_scalar_random()

def crypto_scalarmult_ristretto255_base(n: bytes) -> bytes: # 32-byte input.
    t = bytearray([b for b in n])
    t[31] &= 127
    q = ge25519_p3.scalar_mult_base(t).to_bytes_ristretto255()
    return None if sodium_is_zero(q) else q

def crypto_scalarmult_ristretto255(n: bytes, p: bytes) -> bytes: # 32-byte inputs.
    P = ge25519_p3.from_bytes_ristretto255(p)
    if ristretto255_is_canonical(p) == 0 or P is None:
        return None

    t = bytearray([b for b in n])
    t[31] &= 127

    q = P.scalar_mult(t).to_bytes_ristretto255()
    return None if sodium_is_zero(q) else q

def crypto_core_ristretto255_add(p: bytes, q: bytes) -> bytes:
    p_p3 = ge25519_p3.from_bytes_ristretto255(p)
    q_p3 = ge25519_p3.from_bytes_ristretto255(q)
    if ristretto255_is_canonical(p) == 0 or p_p3 is None or\
       ristretto255_is_canonical(q) == 0 or q_p3 is None:
       return None

    q_cached = ge25519_cached.from_p3(q_p3)
    r_p1p1 = ge25519_p1p1.add(p_p3, q_cached)
    r_p3 = ge25519_p3.from_p1p1(r_p1p1)

    return r_p3.to_bytes_ristretto255()

def crypto_core_ristretto255_sub(p: bytes, q: bytes) -> bytes:
    p_p3 = ge25519_p3.from_bytes_ristretto255(p)
    q_p3 = ge25519_p3.from_bytes_ristretto255(q)
    if ristretto255_is_canonical(p) == 0 or p_p3 is None or\
       ristretto255_is_canonical(q) == 0 or q_p3 is None:
        return None

    q_cached = ge25519_cached.from_p3(q_p3)
    r_p1p1 = ge25519_p1p1.sub(p_p3, q_cached)
    r_p3 = ge25519_p3.from_p1p1(r_p1p1)

    return r_p3.to_bytes_ristretto255()

#
# Generic elliptic curve primitive synonyms: hard-coded to be
# either Ed25519 or Ristretto255.
#

class primitives():
    '''
    Wrapper class for easier merging of modules.
    '''
    
    crypto_generichash_bytes = crypto_generichash_bytes
    crypto_secretbox_noncebytes = crypto_secretbox_noncebytes
    crypto_box_secretkeybytes = crypto_box_secretkeybytes
    crypto_core_ed25519_scalarbytes  = crypto_core_ed25519_scalarbytes
    crypto_generichash = crypto_generichash

    crypto_core_scalar_random = crypto_core_ristretto255_scalar_random
    crypto_scalarmult_base = crypto_scalarmult_ristretto255_base
    crypto_scalarmult = crypto_scalarmult_ristretto255
    crypto_core_add = crypto_core_ristretto255_add
    crypto_core_sub = crypto_core_ristretto255_sub
