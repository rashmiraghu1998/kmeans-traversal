import ctypes
import ctypes.util

sodium = None
try:
    sodium =\
        ctypes.cdll.LoadLibrary(ctypes.util.find_library('sodium') or\
        ctypes.util.find_library('libsodium'))

    #
    # Buffer size constants.
    #

    def crypto_generichash_bytes():
        return sodium.crypto_generichash_bytes()

    def crypto_secretbox_noncebytes():
        return sodium.crypto_secretbox_noncebytes()

    def crypto_box_secretkeybytes():
        return sodium.crypto_box_secretkeybytes()

    def crypto_box_publickeybytes():
        return sodium.crypto_box_publickeybytes()

    def crypto_core_ed25519_bytes():
        return sodium.crypto_core_ed25519_bytes()

    def crypto_core_ed25519_scalarbytes():
        return sodium.crypto_core_ed25519_scalarbytes()

    def crypto_core_ristretto255_bytes():
        return sodium.crypto_core_ristretto255_bytes()

    def crypto_secretbox_macbytes():
        return sodium.crypto_secretbox_macbytes()

    #
    # General libsodium cryptographic primitives.
    #

    def crypto_secretbox_easy(message, nonce, k):
        cipher = ctypes.create_string_buffer(crypto_secretbox_macbytes() + len(message))
        sodium.crypto_secretbox_easy(cipher, message, ctypes.c_ulonglong(len(message)), nonce, k)
        return cipher.raw

    def crypto_secretbox_open_easy(cipher, nonce, k):
        message = ctypes.create_string_buffer(len(cipher) - crypto_secretbox_macbytes())
        sodium.crypto_secretbox_open_easy(message, cipher, ctypes.c_ulonglong(len(cipher)), nonce, k)
        return message.raw

    def crypto_generichash(m, k=b'', outlen=crypto_generichash_bytes()):
        buf = ctypes.create_string_buffer(outlen)
        sodium.crypto_generichash(buf, ctypes.c_size_t(outlen), m, ctypes.c_ulonglong(len(m)), k, ctypes.c_size_t(len(k)))
        return buf.raw

    #
    # Ed25519 primitives for elliptic curve operations.
    #

    def crypto_core_ed25519_scalar_random():
        buf = ctypes.create_string_buffer(crypto_box_secretkeybytes())
        sodium.crypto_core_ed25519_scalar_random(buf)
        return buf.raw

    def crypto_scalarmult_ed25519_base_noclamp(e):
        buf = ctypes.create_string_buffer(crypto_box_publickeybytes())
        sodium.crypto_scalarmult_ed25519_base_noclamp(buf, e)
        return buf.raw

    def crypto_scalarmult_ed25519_noclamp(x, y):
        buf = ctypes.create_string_buffer(crypto_box_secretkeybytes())
        sodium.crypto_scalarmult_ed25519_noclamp(buf, x, y)
        return buf.raw

    def crypto_core_ed25519_add(x, y):
        buf = ctypes.create_string_buffer(crypto_core_ed25519_bytes())
        sodium.crypto_core_ed25519_add(buf, x, y)
        return buf.raw
        
    def crypto_core_ed25519_sub(x, y):
        buf = ctypes.create_string_buffer(crypto_core_ed25519_bytes())
        sodium.crypto_core_ed25519_sub(buf, x, y)
        return buf.raw

    #
    # Ristretto255 primitives for elliptic curve operations.
    #

    def crypto_core_ristretto255_scalar_random():
        buf = ctypes.create_string_buffer(crypto_box_secretkeybytes())
        sodium.crypto_core_ristretto255_scalar_random(buf)
        return buf.raw

    def crypto_scalarmult_ristretto255_base(e):
        buf = ctypes.create_string_buffer(crypto_box_publickeybytes())
        sodium.crypto_scalarmult_ristretto255_base(buf, e)
        return buf.raw

    def crypto_scalarmult_ristretto255(x, y):
        buf = ctypes.create_string_buffer(crypto_box_secretkeybytes())
        sodium.crypto_scalarmult_ristretto255(buf, x, y)
        return buf.raw

    def crypto_core_ristretto255_add(x, y):
        buf = ctypes.create_string_buffer(crypto_core_ristretto255_bytes())
        sodium.crypto_core_ristretto255_add(buf, x, y)
        return buf.raw
        
    def crypto_core_ristretto255_sub(x, y):
        buf = ctypes.create_string_buffer(crypto_core_ristretto255_bytes())
        sodium.crypto_core_ristretto255_sub(buf, x, y)
        return buf.raw

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

except:
    pass
    # raise OSError("libsodium cannot be found")
