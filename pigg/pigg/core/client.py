"""Client object and interface base class.

Base class for client objects that run garbled circuit
protocols with servers.
"""

import zlib
import json
import bitlist
import requests

try:
    from pigg.data.circuits import *
    from pigg.data.label import *
    from pigg.data.assignment import *
    from pigg.data.payload import *
    from pigg.crypto.comm import *
    from pigg.crypto.ot import *
    from pigg.core.evaluate import *
    from pigg.core.server import *
    from pigg.core.cigg import *
except:
    from data.circuits import *
    from data.label import *
    from data.assignment import *
    from pigg.data.payload import *
    from crypto.comm import *
    from crypto.ot import *
    from core.evaluate import *
    from core.server import *
    from core.cigg import *

class ConnectionError(IOError):
    '''
    Raised when there is an issue reaching the server.
    '''

class client():
    '''
    Wrapper class for easier merging of modules.
    '''

    def __init__(
            self, url=None, headers={},
            simulated=None,
            cigg=True, sodium=True
        ):
        self.url = url if simulated is None else None # Simulation overrides URL.
        self.headers = headers
        self.simulated = simulated
        self.lengths = None
        self.cigg = cigg
        self.sodium = sodium

        # Determine whether a native evaluation component is available.
        try:
            self.evaluate = evaluate
        except:
            self.evaluate = None

        # Determine whether a native OT component is available.
        try:
            self.ot = ot
        except:
            self.ot = None

        # If instructed to use only native Python for OT, ensure this is
        # done (wrap in exception handler in case OT module is not in
        # scope, such as if we are using CIGG for the OT steps).
        try:
            self.ot.sodium(self.sodium)
        except:
            pass

        # Check if the server is available and retrieve server input lengths.
        try:
            response = self.request({'api_status':{}})
            if 'status' not in response:
                raise ConnectionError(
                    'server at supplied URL is not configured '+\
                    'properly'
                )
            elif response['status'] != 'available':
                raise ConnectionError(
                    'server at supplied URL is not available'
                )
            elif 'lengths' not in response:
                raise RuntimeError('server response is in improper format and cannot be processed')
            else:
                # Object indicating server input lengths for different circuits.
                self.lengths = response['lengths']
        except requests.exceptions.ConnectionError:
            raise

        # For receiving results from the server.
        self.public_secret_interface = comm.public_secret_interface()

    def request(self, req):
        if self.simulated is None:
            # Any exceptions from `requests` (including connectivity issues
            # and HTTP error responses) are passed back to the caller.
            response = requests.post(url=self.url, headers=self.headers, json=req)
            try:
                return json.loads(response.text)
            except:
                raise RuntimeError('server response is in improper format and cannot be processed')

        else: # Local simulation of server.
            return self.simulated.respond(req)

    def compute(self, circuit_name, input_e, input_g=None, meta={}):
        try:
            # Load specified circuit (from file or cache/embedding).
            c = circuits.load(circuit_name)

            # Obtain the garbled gates and wire-to-label maps.
            data = payload.encode(
                [circuit_name, str(len(input_e)), json.dumps(meta)] +\
                ([input_g] if input_g is not None else [])
            )
        except:
            raise RuntimeError('client object encountered an error')

        response = self.request({'api_gates_wires_keys':data})

        try:
            # Determine if the payload is already present, or else
            # retrieve it in parts.
            keys_or_gates = payload.decode(response[0])
            gates_garbled = None
            if isinstance(keys_or_gates, (bytes, bytearray)):
                gates_garbled = zlib.decompress(keys_or_gates)
            elif isinstance(keys_or_gates, list):
                gates_garbled = bytearray()
                for key in keys_or_gates:
                    resp = self.request({'api_response':payload.encode([key])})
                    part = payload.decode(resp[0])
                    gates_garbled = gates_garbled + bytes(part)
                gates_garbled = zlib.decompress(gates_garbled)
        except:
            raise RuntimeError('client object encountered an error')

        try:
            # Decode and deserialize what is needed at this point; leave the rest.
            wire_in_to_label = Assignment.from_srgg(payload.decode(response[1]))
            wire_in_two_to_labels = response[2] # Sent back to garbler unmodified.
            wire_out_to_labels = response[3] # Sent back to garbler unmodified.
            garbler_keys_secret = response[4] # Sent back to garbler unmodified.
            garbler_keys_public = payload.decode(response[5])
        except:
            raise RuntimeError('server response is in improper format and cannot be processed')

        try:
            # Obtain sender keys, send back selection keys, and get back encrypted label pairs.
            (evaluator_keys_secret, evaluator_keys_public) = (None, None)
            if self.cigg and cigg.lib is not None:
                # Obtain keys for client/evaluator and make messages for server/garbler.
                (evaluator_keys_secret, evaluator_keys_public) =\
                    cigg.client_ot_key_pairs(len(input_e))
                key_for_each_input_two_bit = cigg.client_ot_receiver_send_messages(
                    [b for bs in garbler_keys_public for b in bs],
                    [b for bs in evaluator_keys_public for b in bs],
                    input_e
                )
            elif self.ot is not None:
                # Obtain keys for client/evaluator and make messages for server/garbler.
                (evaluator_keys_secret, evaluator_keys_public) = self.ot.key_pairs(len(input_e))
                key_for_each_input_two_bit = self.ot.receiver_send_messages(
                    garbler_keys_public, evaluator_keys_public,
                    input_e
                )
            else:
                raise RuntimeError('neither CIGG nor native OT component is available')

            data = [
                payload.encode(key_for_each_input_two_bit),
                garbler_keys_secret,
                payload.encode(garbler_keys_public),
                wire_in_two_to_labels
            ]
        except:
            raise RuntimeError('client object encountered an error')

        response = self.request({'api_input_two_labels':data})

        try:
            enc_label_pairs = payload.decode(response)
        except:
            raise RuntimeError('server response is in improper format and cannot be processed')

        try:
            # Decode input label pairs.
            if self.cigg and cigg.lib is not None:
                label_per_bit = cigg.client_ot_receiver_receive_responses(
                    [b for bs in garbler_keys_public for b in bs],
                    [b for bs in evaluator_keys_secret for b in bs],
                    [b for p in enc_label_pairs for bs in p for b in bs],
                    input_e,
                    len(input_e)
                )
            elif self.ot is not None:
                label_per_bit = ot.receiver_receive_responses(
                    garbler_keys_public, evaluator_keys_secret,
                    enc_label_pairs, input_e
                )
            else:
                raise RuntimeError('neither CIGG nor native OT component is available')

            wire_in_to_label.extend([
                [Label.from_bytes(label_per_bit[i])] for i in range(len(input_e))
            ])

            # Decode the garbled gates and evaluate them to obtain output labels.
            if self.cigg and cigg.lib is not None and circuit_name in cigg.embedded:
                wire_out_to_label = cigg.client_evaluate(
                    1 + 4 + c.wire_out_count*(2+16),
                    cigg.embedded.index(circuit_name),
                    bytes(wire_in_to_label.to_srgg()),
                    gates_garbled
                )
            elif self.evaluate is not None:
                gates_garbled = Assignment.from_srgg_opt(gates_garbled)
                wire_to_label = self.evaluate.evaluate_gates_opt(c, gates_garbled, wire_in_to_label)
                wire_out_to_label = wire_to_label.keep_only(c.wire_out_index).to_srgg()
            else:
                raise RuntimeError('neither CIGG nor native evaluation component is available')

            # Have the garbler map the output labels to their corresponding bits
            # and return the bit vector (encrypted with client's public key).
            data = [
                payload.encode(circuit_name),
                wire_out_to_labels,
                payload.encode(wire_out_to_label),
                self.public_secret_interface.key_public_encoded
            ]
        except:
            raise RuntimeError('client object encountered an error')

        response = self.request({'api_bits_from_labels':data})

        try:
            if 'nothing' in response:
                return None
            elif 'bytes' in response:
                return self.public_secret_interface.decrypt(
                    payload.decode(response['bytes'])
                )
            elif 'json' in response:
                return json.loads(
                    self.public_secret_interface.decrypt(
                        payload.decode(response['json'])
                    )
                )
        except:
            raise RuntimeError('server response is in improper format and cannot be processed')
