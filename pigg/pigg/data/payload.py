"""HTTP JSON payload encoding/decoding.

Functions for encoding/decoding byte data into
JSON payloads for HTTP messages.
"""

import base64
import json
import bitlist

try:
    from pigg.data.assignment import *
except:
    from data.assignment import *

class payload():
    '''
    Wrapper class for easier merging of modules.
    '''

    @staticmethod
    def encode(data):
        if type(data) is str:
            return base64.standard_b64encode(data.encode()).decode('utf-8')
        elif type(data) in [bytes, bytearray]:
            return base64.standard_b64encode(data).decode('utf-8')
        elif type(data) is list:
            return [payload.encode(entry) for entry in data]
        elif type(data) is bitlist.bitlist:
            return payload.encode(bytes(list(data)))
        else:
            raise ValueError("cannot encode data of type " + str(type(data)))

    @staticmethod
    def decode(data):
        # Assumes this function is only invoked on Base64 strings.
        if type(data) is str:
            return base64.standard_b64decode(data)
        elif type(data) is list:
            return [payload.decode(entry) for entry in data]
        else:
            raise ValueError("cannot decode data of type " + str(type(data)))
