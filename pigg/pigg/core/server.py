"""Server object and interface base class.

Base class for server objects that can be used to
instatiate garbled circuit protocol services.
"""

import zlib
import parts
import bitlist
import bfcl

try:
    from pigg.data.circuits import *
    from pigg.data.assignment import *
    from pigg.data.payload import *
    from pigg.crypto.comm import *
    from pigg.crypto.ot import *
    from pigg.core.garble import *
    from pigg.core.cigg import *
except:
    from data.circuits import *
    from data.assignment import *
    from data.payload import *
    from crypto.comm import *
    from crypto.ot import *
    from core.garble import *
    from core.cigg import *

class server():
    '''
    Wrapper class for easier merging of modules.
    '''

    def __init__(
            self, path='/',
            key=None, input=None, output=None, 
            cap=None, put=None, get=None, 
            log=(lambda _, __: None),
            server_input_lengths={'*':16}, client_output=False,
            cigg=True, sodium=True
        ):
        self._path = path
        self._func_key = key
        self._func_in = input
        self._func_out = output
        self._func_cap = cap
        self._func_put = put
        self._func_get = get
        self._func_log = log
        self.input_lengths = server_input_lengths
        self.client_output = client_output
        self.cigg = cigg
        self.sodium = sodium

        # Import statement for Flask appears here because this module may
        # be used in circumstances that may not require this method; in that
        # case, there is no need to require flask as a dependency for the
        # entire module.
        try:
            import flask
            self.flask = flask
        except:
            self.flask = None

        # Determine whether a native evaluation component is available.
        try:
            self.garble = garble
        except:
            self.garble = None

        # Determine whether a native OT component is available.
        try:
            self.ot = ot
        except:
            self.ot = None

        # If instructed to use only native Python for OT, ensure this is
        # done (wrap in exception handler in case OT module is not in
        # scope, such as if we are using CIGG for the OT steps).
        try:
            ot.sodium(self.sodium)
        except:
            pass

        # Create a default key function if one has not been supplied.
        if self._func_key is None:
            key = comm.secret_key() # Always use the same key.
            self._func_key = lambda _: key

    def _circuit_reference_for_hooks(self, circuit_name):
        return circuit_name

    def key(self, func_key):
        # Decorator for binding symmetric key function.
        self._func_key = func_key

    def input(self, func_in):
        # Decorator for binding input generator function.
        self._func_in = func_in

    def output(self, func_out):
        # Decorator for binding output handler function.
        self._func_out = func_out

    def cap(self, func_cap):
        # Decorator for binding response size limit function.
        self._func_cap = func_cap

    def put(self, func_put):
        # Decorator for binding response storage function.
        self._func_put = func_put

    def get(self, func_get):
        # Decorator for binding response retrieval function.
        self._func_get = func_get

    def log(self, func_log):
        # Decorator for binding log function.
        self._func_log = func_log

    def respond(self, req):
        '''
        Computes and returns a JSON format reply to the
        supplied JSON format API request.
        '''
        items = req.items()

        # There should only be one request per JSON payload.
        if len(items) != 1:
            return None

        # Parse request command string and dispatch corresponding method.
        try:
            for (cmd, params) in items:
                response = {}
                if cmd.startswith('api_') and hasattr(self, cmd):
                    return getattr(self, cmd)(*params)
                else:
                    return None
        except:
            raise RuntimeError('server error occurred during client request processing')

    def route(self, app):
        '''
        Add the service request handler as a route to the supplied Flask app.
        '''

        # Check if Flask is available and was loaded.
        if self.flask is None:
            raise RuntimeError('Flask package is not installed')

        # Add the route.
        @app.route(self._path, methods=['POST'])
        def service():
            if not self.flask.request.json:
                self._func_log(
                    self,
                    'client request is in improper format and cannot be processed'
                )
                self.flask.abort(400)

            try:
                response = self.respond(self.flask.request.json)
                if response is not None:
                    return (self.flask.jsonify(response), 201)
                else:
                    self._func_log(
                        self,
                        'client request is in improper format and cannot be processed'
                    )
                    self.flask.abort(400)
            except:
                self._func_log(
                    self,
                    'server error occurred during client request processing'
                )
                self.flask.abort(500)

        return app

    #
    # These functions are used to encrypt the state of the computation so that the
    # server can proceed with each stage using the encrypted information about the
    # state at the end of the previous stage. The client simply passes these values
    # back to the server.
    #

    def persistent_key_for_state(self):
        # Generate and store somewhere securely; retrieve it in this function.
        if self._func_key is not None:
            return self._func_key(self)
        else:
            raise ValueError('server key function is missing')

    #
    # Below are the API endpoints for the server status and the interactive protocol.
    #

    def api_status(self):
        return {'status': 'available', 'lengths': self.input_lengths}

    def api_response(self, key):
        if self._func_cap is not None and self._func_get is not None:
            return payload.encode([
                self._func_get(
                    self, self._func_cap(self), 
                    payload.decode(key).decode('utf-8')
                )
            ])
        else:
            return payload.encode([])

    def api_gates_wires_keys(
            self,
            circuit_name, input_e_length, meta,
            input_g=None
        ):
        # Determine the circuit being used and decode the input from the client.
        circuit_name = payload.decode(circuit_name).decode('utf-8')
        input_e_length = int(payload.decode(input_e_length))
        meta = json.loads(payload.decode(meta))

        # Obtain the server-side input.
        if self._func_in is not None and input_g is None:
            input_g = bitlist.bitlist(
                self._func_in(
                    self,
                    self._circuit_reference_for_hooks(circuit_name),
                    input_e_length,
                    meta
                )
            )
        elif self._func_in is None and input_g is not None:
            input_g = payload.decode(input_g)
        elif input_g is None and self._func_in is None:
            raise ValueError('server has no input to contribute')
        elif input_g is not None and self._func_in is not None:
            raise ValueError('two sources of server-side input provided')

        # Perform the initial stage either using native Python or CIGG.
        if self.cigg and cigg.lib is not None and circuit_name in cigg.embedded:
            # Obtain the wire-to-label(s) maps and garbled gates via CIGG.
            (wire_in_one_to_label, wire_in_two_to_labels, wire_out_to_labels, gates_garbled) =\
                cigg.server_get_gates_wires(cigg.embedded.index(circuit_name), input_g, input_e_length)

            # Generate key pairs for OT.
            (garbler_keys_secret, garbler_keys_public) = cigg.server_ot_key_pairs(input_e_length)

            # Compression of random label data does not reduce its size significantly.
            gates_garbled_response = zlib.compress(gates_garbled.raw, level=0)

            # Store object portions for later retrieval if object is too large.
            keys = None
            if self._func_cap is not None:
                cap = self._func_cap(self)
                if len(gates_garbled_response) > cap and self._func_put is not None:
                    keys = self._func_put(self, cap, gates_garbled_response)

            return payload.encode([
                gates_garbled_response if keys is None else keys,
                wire_in_one_to_label.raw,
                wire_in_two_to_labels.raw,
                comm.encrypt_to_self(self.persistent_key_for_state(), wire_out_to_labels.raw),
                [comm.encrypt_to_self(self.persistent_key_for_state(), k) for k in garbler_keys_secret],
                garbler_keys_public
            ])
        elif self.ot is not None and self.garble is not None:
            # Load specified circuit (from file or cache/embedding).
            c = circuits.load(circuit_name)

            # Generate the wire-to-label(s) maps.
            wire_to_labels = self.garble.generate_wire_to_labels_map(c)
            wire_in_one_to_label = self.garble.wire_in_to_label(wire_to_labels, input_g)
            wire_in_two_to_labels =\
                wire_to_labels.keep_only(range(len(input_g), len(input_g)+input_e_length))
            wire_out_to_labels = wire_to_labels.keep_only(c.wire_out_index)

            # Garble the gates in the supplied circuit.
            gates_garbled = self.garble.garble_gates(c, wire_to_labels)

            # Generate key pairs for OT.
            (garbler_keys_secret, garbler_keys_public) = self.ot.key_pairs(input_e_length)

            return payload.encode([
                zlib.compress(gates_garbled.to_srgg(), level=9),
                wire_in_one_to_label.to_srgg(),
                wire_in_two_to_labels.to_srgg(),
                comm.encrypt_to_self(self.persistent_key_for_state(), wire_out_to_labels.to_srgg()),
                [comm.encrypt_to_self(self.persistent_key_for_state(), k) for k in garbler_keys_secret],
                garbler_keys_public
            ])
        else:
            raise RuntimeError('neither CIGG nor native components are available')

    def api_input_two_labels(
            self,
            key_per_input_two_bit, garbler_keys_secret, garbler_keys_public,
            wire_in_two_to_labels
        ):
        garbler_keys_secret = [
            comm.decrypt_from_self(self.persistent_key_for_state(), k)
            for k in payload.decode(garbler_keys_secret)
        ]
        garbler_keys_public = payload.decode(garbler_keys_public)
        key_per_bit_of_input_two = payload.decode(key_per_input_two_bit)
        messages = Assignment.from_srgg(payload.decode(wire_in_two_to_labels))
        if self.cigg and cigg.lib is not None:
            return payload.encode(cigg.server_ot_sender_send_responses(
                [b for bs in garbler_keys_secret for b in bs],
                [b for bs in garbler_keys_public for b in bs],
                [b for bs in key_per_bit_of_input_two for b in bs],
                [b for pair in messages for lbl in pair for b in lbl.bytes()],
                len(messages)
            ))
        elif self.ot is not None:
            return payload.encode(self.ot.sender_send_responses(
                garbler_keys_secret,
                garbler_keys_public,
                key_per_bit_of_input_two,
                messages
            ))
        else:
            raise RuntimeError('neither CIGG nor native OT component is available')

    def api_bits_from_labels(
            self, circuit_name, wire_out_to_labels, wire_out_to_label,
            client_public_key_encoded
        ):
        # Decode the circuit name.
        circuit_name = payload.decode(circuit_name).decode()
        
        # Obtain the original output labels from the server.
        wire_out_to_labels = Assignment.from_srgg(
            comm.decrypt_from_self(
                self.persistent_key_for_state(),
                payload.decode(wire_out_to_labels)
            )
        )

        # Obtain the output labels from client-side evaluation.
        wire_out_to_label = Assignment.from_srgg(payload.decode(wire_out_to_label))

        # Obtain the output bit vector.
        bs = self.output_labels_to_bits(wire_out_to_labels, wire_out_to_label)

        # If a hook has been specified for processing the output bit vector, invoke it.
        if self._func_out is not None:
            output = self._func_out(
                self,
                self._circuit_reference_for_hooks(circuit_name),
                bs.to_bytes()
            )

            if not self.client_output:
                return {'nothing': []}
            elif isinstance(output, bytes) or isinstance(output, bytearray):
                # Encode/encrypt and return the result for delivery back to the client.
                return {'bytes': payload.encode(
                    comm.encrypt_to_other(client_public_key_encoded, bs.to_bytes())
                )}
            elif isinstance(output, dict):
                # Encode/encrypt and return the result for delivery back to the client.
                return {'json': payload.encode(
                    comm.encrypt_to_other(
                        client_public_key_encoded, json.dumps(output).encode()
                    )
                )}
            else:
                return {'nothing': []}
        else:
            return {'nothing': []}

    def output_labels_to_bits(self, wire_out_to_labels, wire_out_to_label):
        bs = []

        for i in range(len(wire_out_to_labels)):
            wire_out_lbls = wire_out_to_labels[i]
            output_label = wire_out_to_label[i][0]

            if wire_out_lbls[0] == output_label:
                bs.append(0)
            elif wire_out_lbls[1] == output_label:
                bs.append(1)
            else:
                raise ValueError("wrong output label in `output_labels_to_bits(...)`")

        return bitlist.bitlist(bs)
