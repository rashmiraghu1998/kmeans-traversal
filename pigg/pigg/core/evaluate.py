"""Garbled circuit protocol evaluator implementation.

Protocol steps that the evaluator performs in a garbled circuits
protocol instance.
"""

import bfcl

try:
    from pigg.data.label import *
    from pigg.crypto.simple import *
except:
    from pigg.pigg.data.label import *
    from pigg.pigg.crypto.simple import *

class evaluate():
    '''
    Wrapper class for easier merging of modules.
    '''

    @staticmethod
    def evaluate_gate(gate, gate_garbled, wire_to_labels, gate_id):
        try:
            x_label_0 = wire_to_labels[gate.wire_in_index[0]][0]

            if gate.operation == bfcl.op.not_:
                wire_to_labels[gate.wire_out_index[0]] = [x_label_0]

            elif gate.operation in [
                    bfcl.op.and_, bfcl.op.xor_, bfcl.op.or_, bfcl.op.nand_,
                    bfcl.op.nimp_, bfcl.op.nif_, bfcl.op.xnor_
                ]:
                y_label_0 = wire_to_labels[gate.wire_in_index[1]][0]
                color = 2*x_label_0.extract() + y_label_0.extract()

                data = simple.decrypt(
                    x_label_0, y_label_0, gate_id, gate_garbled[color]
                )

                wire_to_labels[gate.wire_out_index[0]] = [Label(data)]

            # elif gate.operation == bfcl.op.xor_: # The "free XOR" optimization.
            #     y_label_0 = wire_to_labels[gate.wire_in_index[1]][0]
            #     wire_to_labels[gate.wire_out_index[0]] = [x_label_0 ^ y_label_0]

            else:
                raise ValueError(
                    'operation "' + gate.operation.name() +\
                    '" not supported in gate evaluation'
                )
        except:
            pass

    @staticmethod
    def evaluate_gates(circuit, gates_garbled, wire_to_labels):
        wire_to_labels.extend([None] * (circuit.wire_count - len(wire_to_labels)))

        for i in range(len(gates_garbled)):
            evaluate.evaluate_gate(circuit.gate[i], gates_garbled[i], wire_to_labels, i)

        return wire_to_labels

    @staticmethod
    def evaluate_gates_opt(circuit, gates_garbled, wire_to_labels):
        wire_to_labels.extend([None] * (circuit.wire_count - len(wire_to_labels)))

        for i in range(len(gates_garbled)):
            gate = circuit.gate[i]
            gate_garbled = gates_garbled[i]

            x_label_0 = wire_to_labels[gate.wire_in_index[0]][0]

            if gate.operation == bfcl.op.not_:
                wire_to_labels[gate.wire_out_index[0]] = [x_label_0]

            else:
            # elif gate.operation in [
            #     bfcl.op.and_, bfcl.op.xor_, bfcl.op.or_, bfcl.op.nand_,
            #     bfcl.op.nimp_, bfcl.op.nif_, bfcl.op.xnor_
            # ]:
                y_label_0 = wire_to_labels[gate.wire_in_index[1]][0]
                color = 2*x_label_0.extract() + y_label_0.extract()

                data = simple.decrypt(
                    x_label_0, y_label_0, i,
                    Label.from_bytes(gate_garbled[color*16:(color+1)*16])
                )

                wire_to_labels[gate.wire_out_index[0]] = [Label(data)]

        return wire_to_labels
