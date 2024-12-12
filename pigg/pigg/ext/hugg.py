"""HUGG client object and interface.

Client object and API for specialized HUGG library variant.
"""

import bitlist

try:
    from pigg.data.payload import *
    from pigg.core.client import *
except:
    from data.payload import *
    from core.client import *

class _constant():
    sha256 = 'sha256'
    aes128_ecb_encrypt = 'aes128_ecb_encrypt'
    aes128_ecb_decrypt = 'aes128_ecb_decrypt'

class hugg(client):
    '''
    Client API of dedicated hashing modules
    that can be merged from the PIGG library.
    '''

    # Function identifier constants for use in hooks.
    constant = _constant

    def _sha256_pad(self, bs, huggs_input_length_in_bytes):
        '''Input bit vector padding for SHA-256.'''
        length = len(bs) + (huggs_input_length_in_bytes * 8)
        bound = 512 if length <= 440 else (1024 if length <= 952 else None)
        return\
            bs+\
            bitlist.bitlist([1] + [0]*7 + [0]*((bound-64-8)-length))+\
            bitlist.bitlist(length, 16)

    def _sha256_huggs_input_length(self):
        huggs_input_length = 16
        if self.lengths is not None:
            if 'sha256' in self.lengths:
                huggs_input_length = self.lengths['sha256']
            elif '*' in self.lengths:
                huggs_input_length = self.lengths['*']
            else:
                raise ValueError('length of server input not known')
        return huggs_input_length

    def sha256(self, val=None, meta={}):
        '''Client function for computing SHA-256 hash with server.'''
        if not isinstance(val, bytes) and\
           not isinstance(val, bytearray):
            raise ValueError('a bytes-like object is required')

        huggs_input_len_in_bytes = self._sha256_huggs_input_length()

        if len(val) <= 55 - huggs_input_len_in_bytes:
            circuit_name = 'sha-256-for-lteq-440-bits'
        elif len(val) <= 119 - huggs_input_len_in_bytes:
            circuit_name = 'sha-256-for-lteq-952-bits'
        else:
            raise ValueError('value can be at most ' + str(119 - huggs_input_len_in_bytes) + ' bytes in length')

        return self.compute(
            circuit_name,
            self._sha256_pad(bitlist.bitlist(val), huggs_input_len_in_bytes),
            None,
            meta=meta
        )

    def aes128_ecb_encrypt(self, key=None, val=None, meta={}):
        '''Client function for computing AES-128 encryption with server.'''
        if (not isinstance(key, bytes) and\
            not isinstance(key, bytearray) and\
            not key is None) or\
           (not isinstance(val, bytes) and\
            not isinstance(val, bytearray)):
            raise ValueError('a bytes-like object is required')

        if key is not None and len(key) != 16:
            raise ValueError('key must be exactly 16 bytes in length')

        if val is not None and len(val) != 16:
            raise ValueError('value must be exactly 16 bytes in length')

        return self.compute(
            'aes-128-ecb-encrypt',
            bitlist.bitlist(val),
            None if key is None else bitlist.bitlist(key),
            meta=meta
        )

    def aes128_ecb_decrypt(self, key=None, val=None, meta={}):
        '''Client function for computing AES-128 decryption with server.'''
        if (not isinstance(key, bytes) and\
            not isinstance(key, bytearray) and\
            not key is None) or\
           (not isinstance(val, bytes) and\
            not isinstance(val, bytearray)):
            raise ValueError('a bytes-like object is required')

        if key is not None and len(key) != 16:
            raise ValueError('key must be exactly 16 bytes in length')

        if val is not None and len(val) != 16:
            raise ValueError('value must be exactly 16 bytes in length')

        return self.compute(
            'aes-128-ecb-decrypt',
            bitlist.bitlist(val),
            None if key is None else bitlist.bitlist(key),
            meta=meta
        )
