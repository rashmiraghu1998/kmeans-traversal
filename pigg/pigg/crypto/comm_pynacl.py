"""Secure communications primitives.

Functions for secure communications with oneself (via secret-key
cryptography) and with others (via public-key cryptography).
"""

import nacl.utils
import nacl.encoding
import nacl.secret
import nacl.public

class comm_pynacl():
    '''
    Wrapper class for easier merging of modules.
    '''

    @staticmethod
    def secret_key():
        return nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

    @staticmethod
    def encrypt_to_self(key, data):
        return bytes(nacl.secret.SecretBox(key).encrypt(data))

    @staticmethod
    def decrypt_from_self(key, data):
        return nacl.secret.SecretBox(key).decrypt(data)

    @staticmethod
    def encrypt_to_other(key, data):
        public_key = nacl.public.PublicKey(
            key, encoder=nacl.encoding.Base64Encoder
        )
        return bytes(nacl.public.SealedBox(public_key).encrypt(data))

    @staticmethod
    def public_secret_interface():
        class public_secret_interface():
            pass
        interface = public_secret_interface()
        interface.seal = nacl.public.PrivateKey.generate()
        interface.key_public_encoded =\
            interface.seal.public_key\
                     .encode(encoder=nacl.encoding.Base64Encoder)\
                     .decode()
        interface.unseal = nacl.public.SealedBox(interface.seal)
        interface.decrypt = lambda cipher: interface.unseal.decrypt(cipher)
        return interface

# Generic synonym.
comm = comm_pynacl
