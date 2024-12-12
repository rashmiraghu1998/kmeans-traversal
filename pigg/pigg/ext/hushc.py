"""HUSH client object and interface.

Client object and API for specialized HUSH library variant.
"""

import bitlist

try:
    from pigg.data.payload import *
    from pigg.crypto.hush import *
    from pigg.ext.hugg import *
except:
    from data.payload import *
    from crypto.hush import *
    from ext.hugg import *

# Add function identifier constant for HUSH.
hugg.constant.hush = 'hush'

class hushc(hugg):
    '''
    Client API of dedicated hashing modules
    that can be merged from the PIGG library.
    '''

    def hush(self, val=None):
        '''Client function for computing HUSH salted hash.'''
        if (not isinstance(val, bytes) and\
            not isinstance(val, bytearray)):
            raise ValueError('a bytes-like object is required')

        try:
            hashed_value = hush.point(val)
            mask = hush.scalar()
            masked_hashed_value = hush.mul(mask, hashed_value)
        except:
            raise RuntimeError('client object encountered an error')

        response = requests.post(url=self.url, json={
            'api_hush_salt': [{
                'masked@client_hash': payload.encode(masked_hashed_value)
            }]
        })

        try:
            data = json.loads(response.text)
            masked_salted_masked_hash = payload.decode(
                data['masked@server_salted_masked@client_hash']
            )
        except:
            raise RuntimeError(
                'server response is in improper format and cannot be processed'
            )

        try:
            masked_salted_hash = hush.mul(hush.inv(mask), masked_salted_masked_hash)
        except:
            raise RuntimeError('client object encountered an error')

        response = requests.post(url=self.url, json={
            'api_hush_deliver': [{
                'masked@server_salted_hash':
                    payload.encode(masked_salted_hash),
                'mask@server':
                    data['mask@server'],
                'public_key@client':
                    self.public_secret_interface.key_public_encoded
            }]
        })

        try:
            salted_hash = self.public_secret_interface.decrypt(payload.decode(
                json.loads(response.text)['salted_hash']
            ))
        except:
            raise RuntimeError(
                'server response is in improper format and cannot be processed'
            )

        return salted_hash
