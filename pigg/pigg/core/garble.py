"""Garbled circuit protocol garbler implementation.

Protocol steps that the garbler performs in a garbled circuits
protocol instance.
"""

import random
import bitlist
import bfcl

try:
    from pigg.data.label import *
    from pigg.data.assignment import *
    from pigg.crypto.simple import *
except:
    from pigg.pigg.data.label import *
    from pigg.pigg.data.assignment import *
    from pigg.pigg.crypto.simple import *

class garble():
    '''
    Wrapper class for easier merging of modules.
    '''

    @staticmethod
    def generate_label_pair_with_offset(offset):
        # This is used for the "free XOR" optimization.
        point_zero = random.choice([0, 1])
        point_one = 1 - point_zero

        label_0 = Label.random()
        label_0.inject(point_zero)

        label_1 = label_0 ^ offset
        label_1.inject(point_one)

        return [label_0, label_1]

    @staticmethod
    def generate_label_pair():
        point_zero = random.choice([0, 1])
        point_one = 1 - point_zero

        label_0 = Label.random()
        label_0.inject(point_zero)

        label_1 = Label.random()
        label_1.inject(point_one)

        return [label_0, label_1]

    @staticmethod
    def generate_label_pair_deterministic(i):
        point_zero = 0
        point_one = 1 - point_zero

        label_0 = Label.deterministic(i*2)
        label_0.inject(point_zero)

        label_1 = Label.deterministic(i*2 + 1)
        label_1.inject(point_one)

        return [label_0, label_1]

    @staticmethod
    def generate_wire_to_labels_map(circuit):
        wire_to_labels = Assignment([None] * circuit.wire_count)

        # Rejection sampling: labels common to a wire should be distinct.
        offset = Label.random_non_zero()
        offset.inject(1)

        for i in range(circuit.wire_in_count):
            # # For debugging purposes.
            # wire_to_labels[circuit.wire_in_index[i]] = garble.generate_label_pair_deterministic(i)
            wire_to_labels[circuit.wire_in_index[i]] = garble.generate_label_pair()

        for i in range(circuit.gate_count):
            x_wire = circuit.gate[i].wire_in_index[0]
            z_wire = circuit.gate[i].wire_out_index[0]

            if circuit.gate[i].operation == bfcl.op.not_:
                z_label_0 = wire_to_labels[x_wire][1]
                z_label_1 = wire_to_labels[x_wire][0]
                wire_to_labels[z_wire] = [z_label_0, z_label_1]

            elif circuit.gate[i].operation in\
                    [bfcl.op.and_, bfcl.op.xor_, bfcl.op.or_, bfcl.op.nand_,
                     bfcl.op.nimp_, bfcl.op.nif_, bfcl.op.xnor_]:
                # # For debugging purposes.
                # wire_to_labels[z_wire] = garble.generate_label_pair_deterministic(circuit.wire_in_count + i)
                wire_to_labels[z_wire] = garble.generate_label_pair()

            # elif circuit.gate[i].operation == bfcl.op.xor_: # The "free XOR" optimization.
            #     y_wire = circuit.gate[i].wire_in_index[1]
            #     x_label_0 = wire_to_labels[x_wire][0]
            #     y_label_0 = wire_to_labels[y_wire][0]
            #
            #     z_label_0 = x_label_0 ^ y_label_0
            #     z_label_0_point = x_label_0.extract() ^ y_label_0.extract()
            #     z_label_0.inject(z_label_0_point)
            #
            #     z_label_1 = z_label_0 ^ offset
            #     z_label_1.inject(z_label_0_point ^ 1)
            #
            #     wire_to_labels[z_wire] = [z_label_0, z_label_1]



        return wire_to_labels

    @staticmethod
    def wire_in_to_label(wire_to_labels, input):
        return Assignment([wire_to_labels[i][int(input[i])]] for i in range(len(input)))

    @staticmethod
    def garble_gate_operation(gate_from_circuit, wire_to_labels, gate_id, outputs):
        # The `outputs` parameter specifies the two-argument logical operator's
        # outputs corresponding to the inputs (in the same order) `(0,0)`, `(0,1)`,
        # `(1,0)`, and `(1,1)`.

        x_labels = wire_to_labels[gate_from_circuit.wire_in_index[0]]
        y_labels = wire_to_labels[gate_from_circuit.wire_in_index[1]]
        z_labels = wire_to_labels[gate_from_circuit.wire_out_index[0]]

        colors = [
            x_labels[0].extract()*2 + y_labels[0].extract(),
            x_labels[0].extract()*2 + y_labels[1].extract(),
            x_labels[1].extract()*2 + y_labels[0].extract(),
            x_labels[1].extract()*2 + y_labels[1].extract()
        ]

        # Encrypt result.
        values = [
            simple.encrypt(x_labels[0], y_labels[0], gate_id, z_labels[outputs[0]]),
            simple.encrypt(x_labels[0], y_labels[1], gate_id, z_labels[outputs[1]]),
            simple.encrypt(x_labels[1], y_labels[0], gate_id, z_labels[outputs[2]]),
            simple.encrypt(x_labels[1], y_labels[1], gate_id, z_labels[outputs[3]])
        ]

        # Order values according to the order of colors; set select_bit to
        # the value that is the binary representation of 2*color_x_0/1+color_y_0/1.
        gate_garbled = [None, None, None, None]
        for i in range(4):
            gate_garbled[colors[i]] = Label(values[i])

        return gate_garbled

    @staticmethod
    def garble_gate(gate, wire_to_labels, gate_id):
        if gate.operation == bfcl.op.not_:
            return []
        elif gate.operation in\
                [bfcl.op.and_, bfcl.op.xor_, bfcl.op.or_, bfcl.op.nand_,
                 bfcl.op.nimp_, bfcl.op.nif_, bfcl.op.xnor_]:
            # We do not use the "free XOR" optimization due to patent
            # restrictions. To utilize it, simply remove `bfcl.op.xor_` from
            # the list in the condition for this block.
            return garble.garble_gate_operation(
                gate, wire_to_labels, gate_id,
                gate.operation # Operator outputs as a tuple for 00,01,10,11.
            )


    @staticmethod
    def garble_gates(circuit, wire_to_labels):
        return Assignment(
            garble.garble_gate(circuit.gate[i], wire_to_labels, i)
            for i in range(circuit.gate_count)
        )

    @staticmethod
    def output_labels_to_bits(wire_out_to_labels, wire_out_to_label):
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
