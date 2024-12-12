"""Primitives for garbled circuit protocols.

Simple cryptographic primitives for garbling
operations in a garbled circuit protocol.
"""

import nacl.bindings

try:
    from pigg.data.label import *
except:
    from pigg.pigg.data.label import *

# Toggle to disable randomized gate labels and gate label
# encryption/decryption (for debugging purposes).
CRYPTO_SIMPLE_IDENTITY = 0

class simple():
    '''
    Wrapper class for easier merging of modules.
    '''

    # This is used to concatenate the bits of two
    # label integers; the concrete value is
    # `340282366920938463463374607431768211456`
    # and appears in `encrypt()` below.
    concat_factor = (2**(8*Label.LABEL_LENGTH))

    @staticmethod
    def encrypt(key1, key2, gate_id, message):
        cbc_key_gate_id = simple.block_cipher(
            (key2.int*340282366920938463463374607431768211456 + key1.int)\
                .to_bytes(32, 'little'),
            gate_id.to_bytes(4, 'little') + bytes(28)
        )
        return message.int ^ int.from_bytes(cbc_key_gate_id, 'little')

    @staticmethod
    def decrypt(key1, key2, gate_id, cipher):
        return simple.encrypt(key1, key2, gate_id, cipher)

    @staticmethod
    def block_cipher(key, message):
        return nacl.bindings.crypto_aead_chacha20poly1305_encrypt(message, bytes(8), bytes(8), bytes(key))

    @staticmethod
    def identity(key1, key2, gate_id, message_or_cipher):
        return message_or_cipher.int

if CRYPTO_SIMPLE_IDENTITY == 1:
    simple.encrypt = simple.identity
    simple.decrypt = simple.identity
