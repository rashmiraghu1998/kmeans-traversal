"""HUGG server object and interface.

Server object and API for specialized HUGG library variant.
"""

try:
    from pigg.data.payload import *
    from pigg.crypto.comm import *
    from pigg.core.server import *
except:
    from data.payload import *
    from crypto.comm import *
    from core.server import *

class _constant():
    sha256 = 'sha256'
    aes128_ecb_encrypt = 'aes128_ecb_encrypt'
    aes128_ecb_decrypt = 'aes128_ecb_decrypt'

class huggs(server):
    '''
    Server API of dedicated hashing modules
    that can be merged from the PIGG library.
    '''

    # Function identifier constants for use in hooks.
    constant = _constant

    def _circuit_reference_for_hooks(self, circuit_name):
        '''Hook to map circuit names to constants for HUGG API.'''
        return {
            'sha-256-for-lteq-440-bits': 'sha256',
            'sha-256-for-lteq-952-bits': 'sha256',
            'aes-128-ecb-encrypt': 'aes128_ecb_encrypt',
            'aes-128-ecb-decrypt': 'aes128_ecb_decrypt'
        }.get(circuit_name, circuit_name)
