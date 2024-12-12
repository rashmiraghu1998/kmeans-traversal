"""Embedded circuit management.

Class for managing a collection of embedded logic circuits.
"""

import os
import zlib
import base64
import pickle
import bfcl

class circuits():
    '''
    Wrapper class for easier merging of modules.
    '''

    # Cache ensuring that circuits are only loaded once from disk.
    cache = {}

    # Dictionary to store data for embedded circuits.
    embedded = {}

    @staticmethod
    def load(circuit_name):
        if circuit_name in circuits.embedded:
            return circuits.extract(circuits.embedded[circuit_name])
        else:
            if circuit_name not in circuits.cache:
                path = 'circuit/bristol/' + circuit_name + '.txt'
                path = ('pigg/'+path) if not os.path.exists(path) else path
                circuits.cache[circuit_name] = bfcl.circuit(open(path).read())
            return circuits.cache[circuit_name]

    @staticmethod
    def extract_int(emb, offset, size):
        return (offset + size, int.from_bytes(emb[offset:offset+size], 'big'))

    @staticmethod
    def deserialize(data):
        # The circuit instance that will be returned.
        c = bfcl.circuit()

        # Skip the length values; we do not need them here.
        offset = 5*4

        # Overall dimensions of circuit.
        (offset, c.gate_count) = circuits.extract_int(data, offset, 3)
        (offset, c.wire_count) = circuits.extract_int(data, offset, 3)

        # Circuit input signature.
        c.value_in_count = 2
        (offset, cvil_0) = circuits.extract_int(data, offset, 3)
        (offset, cvil_1) = circuits.extract_int(data, offset, 3)
        c.value_in_length = [cvil_0, cvil_1]

        # Circuit output signature.
        c.value_out_count = 1
        (offset, cvol_0) = circuits.extract_int(data, offset, 3)
        c.value_out_length = [cvol_0]

        # Explicit input/output wire index lists.
        c.wire_in_count = sum(c.value_in_length)
        c.wire_in_index = list(range(c.wire_in_count))
        c.wire_out_count = c.value_out_length[0]
        wire_out_index_first = c.wire_count - c.wire_out_count
        c.wire_out_index = list(range(wire_out_index_first, c.wire_count))

        # Decode the gate collection from the embedded format.
        wire_out_index_ = c.wire_in_count # Begins after last input wire.

        c.gate = []
        for gate_index in range(c.gate_count):
            # Decode the flags from the first entry in the
            # sequence of entries for the next gate.
            operation_bits = data[offset] % 8
            input_one_byte_count = (data[offset] >> 3) % 4
            input_two_byte_count = (data[offset] >> 5) % 4
            common_pattern_encoded = (data[offset] >> 7) % 2
            common_pattern_code = (data[offset] >> 3) % 16
            offset += 1
            operation = [
                bfcl.op.xor_, bfcl.op.nand_, bfcl.op.or_, bfcl.op.and_,
                bfcl.op.not_, bfcl.op.nimp_, bfcl.op.nif_, bfcl.op.xnor_
            ][operation_bits]

            # Extract the gate wire input index information.
            if operation == bfcl.op.not_:
                # Construct the first input wire index.
                (offset, wire_in_index_one) =\
                    circuits.extract_int(data, offset, input_one_byte_count)

                # Restore the output wire index offset.
                wire_in_index_one = wire_out_index_ - wire_in_index_one

                c.gate.append(bfcl.gate(
                    1, 1, [wire_in_index_one], [wire_out_index_], operation
                ))
            else:
                # Assemble the shifted input indices.
                (wire_in_index_one, wire_in_index_two) = (None, None)
                if common_pattern_encoded:
                    (wire_in_index_one, wire_in_index_two) = [
                        (1, 2), (2, 1), (4, 1), (64, 32),
                        (593, 185), (591, 183), (183, 431), (185, 433),
                        (595, 187), (187, 435), (1, 4), (183, 10671),
                        (185, 10673), (187, 10675), (4, 5), (1, 303)
                    ][common_pattern_code]
                else:
                    # Construct the first and second input wire index.
                    (offset, wire_in_index_one) =\
                        circuits.extract_int(data, offset, input_one_byte_count)
                    (offset, wire_in_index_two) =\
                        circuits.extract_int(data, offset, input_two_byte_count)

                # Restore the output wire index offset.
                wire_in_index_one = wire_out_index_ - wire_in_index_one
                wire_in_index_two = wire_out_index_ - wire_in_index_two

                c.gate.append(bfcl.gate(
                    2, 1,
                    [wire_in_index_one, wire_in_index_two],
                    [wire_out_index_],
                    operation
                ))

            wire_out_index_ += 1

        return c

    @staticmethod
    def extract(embedded):
        # If the embedding is a string, it must be a Base64 string.
        if isinstance(embedded, str):
            embedded = base64.standard_b64decode(embedded.replace("\n", ""))

        # The data is always compressed.
        embedded = zlib.decompress(embedded)

        if embedded[0] == 0: # Custom serialization.
            return circuits.deserialize(embedded[1:])
        else: # Pickled.
            return pickle.loads(embedded[1:])
