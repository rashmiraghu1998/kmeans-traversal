"""HUSH server object and interface.

Server object and API for specialized HUSH library variant.
"""

try:
    from pigg.data.payload import *
    from pigg.crypto.comm import *
    from pigg.crypto.hush import *
    from pigg.ext.huggs import *
except:
    from data.payload import *
    from crypto.comm import *
    from crypto.hush import *
    from ext.huggs import *

# Add function identifier constant for HUSH.
huggs.constant.hush = 'hush'

class hushs(huggs):
    '''
    Server API of dedicated hashing modules
    that can be merged from the PIGG library.
    '''

    def api_hush_salt(self, request):
        '''HUSH protocol initial server step.'''

        masked_hash = payload.decode(request['masked@client_hash'])
        salt = hush.scalar(self._func_in(self, hush, 256))
        mask = hush.scalar(bytes([0]))
        masked_salted_masked_hash = hush.mul(mask, hush.mul(salt, masked_hash))
        return {
            'masked@server_salted_masked@client_hash':
                payload.encode(masked_salted_masked_hash),
            'mask@server':
                payload.encode(
                    comm.encrypt_to_self(self.persistent_key_for_state(), mask)
                )
        }

    def api_hush_deliver(self, request):
        '''HUSH protocol final server step.'''

        # Obtain the already salted hash that only has
        # the server mask remaining on it and unmask it
        # using the server mask.
        masked_salted_hash = payload.decode(
            request['masked@server_salted_hash']
        )
        mask = hush.scalar(
            comm.decrypt_from_self(
                self.persistent_key_for_state(),
                payload.decode(request['mask@server'])
            )
        )
        salted_hash = bytes(hush.mul(hush.inv(mask), masked_salted_hash))

        # Return the result to the output hook.
        self._func_out(self, 'hush', salted_hash)

        # Encrypt and return the salted hash to the client.
        return {'salted_hash': payload.encode(
            comm.encrypt_to_other(request['public_key@client'], salted_hash)
        )}
