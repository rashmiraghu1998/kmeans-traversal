"""HUSH elliptic curve operations.

Elliptic curve operations necessary for the HUSH
protocol.
"""

import hashlib
import secrets
import nacl.encoding
import nacl.hash
import ge25519

#
# Ed25519 primitives for elliptic curve operations.
#

try:
    import ctypes
    import ctypes.util

    sodium =\
        ctypes.cdll.LoadLibrary(ctypes.util.find_library('sodium') or\
        ctypes.util.find_library('libsodium'))

    def _crypto_scalarmult_ed25519_noclamp(x, y):
        buf = ctypes.create_string_buffer(sodium.crypto_box_secretkeybytes())
        sodium.crypto_scalarmult_ed25519_noclamp(buf, x, y)
        return buf.raw

    def _crypto_core_ed25519_from_uniform(r):
        buf = ctypes.create_string_buffer(32)
        sodium.crypto_core_ed25519_from_uniform(buf, r)
        return buf.raw
except:
    def _zero(n: bytes) -> int: # 32-byte input.
        d = 0
        for i in range(len(n)):
            d |= n[i]
        return 1 & ((d - 1) >> 8)

    def _crypto_scalarmult_ed25519_is_inf(s: bytes) -> int: # 32-byte input.
        c = s[0] ^ 1
        for i in range(1, 31):
            c |= s[i]
        c |= s[31] & 127
        return ((c - 1) >> 8) & 1

    def _crypto_scalarmult_ed25519(n: bytes, p: bytes, clamp: int) -> bytes:
        P = ge25519.ge25519_p3.from_bytes(p)
        if ge25519.ge25519.is_canonical(p) == 0 or ge25519.ge25519.has_small_order(p) != 0 or\
           P.root_check != 0 or P.is_on_main_subgroup() == 0:
            return None

        t = bytearray([b for b in n])
        if clamp != 0:
            t[0] &= 248
            t[31] |= 64

        t[31] &= 127

        q = P.scalar_mult(t).to_bytes()
        if _crypto_scalarmult_ed25519_is_inf(q) != 0 or _zero(n) == 1:
            return None

        return q

    def _crypto_scalarmult_ed25519_noclamp(n: bytes, p: bytes) -> bytes:
        return _crypto_scalarmult_ed25519(n, p, 0)

    def _crypto_core_ed25519_from_uniform(r):
        return ge25519.ge25519_p3.from_uniform(r).to_bytes()

class hush():
    '''
    Wrapper class for easier merging of modules.
    '''

    prime = pow(2, 252) + 27742317777372353535851937790883648493

    @staticmethod
    def crypto_generichash(m):
        return nacl.hash.blake2b(bytes(m), encoder=nacl.encoding.RawEncoder)

    @staticmethod
    def point(b):
        return _crypto_core_ed25519_from_uniform(hush.crypto_generichash(b))

    @staticmethod
    def scalar(b=None):
        maxUniform = pow(2, 32 * 8) // hush.prime
        maxUniform = maxUniform * hush.prime

        b = secrets.token_bytes(32) if b is None else b

        reducedRandom = None
        r = 0
        b = hashlib.sha256(b).digest()
        while r == 0 or not r < maxUniform:
            r = int.from_bytes(b, 'little') % hush.prime
            b = hashlib.sha256(b).digest()

        return r.to_bytes(32, 'little')

    @staticmethod
    def mul(s, p):
        return _crypto_scalarmult_ed25519_noclamp(s, p)

    @staticmethod
    def inv(s):
        return pow(int.from_bytes(s, 'little'), hush.prime-2, hush.prime).to_bytes(32, 'little')
