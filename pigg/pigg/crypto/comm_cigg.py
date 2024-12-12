"""Secure communications primitives.

Functions for secure communications with oneself (via secret-key
cryptography) and with others (via public-key cryptography).
"""

try:
    assert(cigg.lib is not None)
except:
    raise("CIGG has not been loaded")

import base64
import secrets

class comm_cigg():
    '''
    Wrapper class for easier merging of modules.
    '''

    @staticmethod
    def secret_key():
        return bytes(secrets.token_bytes(32))

    @staticmethod
    def encrypt_to_self(key, data):
        return cigg.server_encrypt_to_self(key, data)

    @staticmethod
    def decrypt_from_self(key, data):
        return cigg.server_decrypt_from_self(key, data)

    @staticmethod
    def encrypt_to_other(key, data):
        # Placeholder; assumes reliance on HTTPS for
        # server-to-client communications security;
        return data

    @staticmethod
    def public_secret_interface():
        # Placeholder; assumes reliance on HTTPS for
        # server-to-client communications security;
        class public_secret_interface():
            pass
        interface = public_secret_interface()
        interface.key_public_encoded =\
            base64.standard_b64encode(bytes([0]*32)).decode('utf-8')
        interface.decrypt = lambda data: data
        return interface

# Generic synonym.
comm = comm_cigg
