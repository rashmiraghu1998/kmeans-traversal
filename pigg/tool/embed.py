import os
from zlib import compress
import base64
import pickle
from random import choice
from parts import parts
from flats import flats
from tqdm import tqdm
from bfcl import circuit, op

def int_to_bytes_min(n):
    if n >= 256 * 256:
        return (3, n.to_bytes(3, 'big'))
    elif n >= 256:
        return (2, n.to_bytes(2, 'big'))
    else:
        return (1, n.to_bytes(1, 'big'))

def serialize(circuit):
    operations_supported = [
        op.xor_, op.nand_, op.or_, op.and_,
        op.not_, op.nimp_, op.nif_, op.xnor_
    ]

    data = bytearray()
    gate = {o.name():0 for o in operations_supported}
    patterns = {}

    # Add circuit attributes exclusive of gate data.
    data.extend(bytes(flats([[b for b in n.to_bytes(3, 'big')] for n in [
        circuit.gate_count, 
        circuit.wire_count,
        circuit.value_in_length[0],
        circuit.value_in_length[1],
        circuit.value_out_length[0]
    ]])))

    # Encode the gate data.
    for (i, g) in tqdm(list(zip(range(len(circuit.gate)), circuit.gate)), desc = ' * encoding gate data'):
        gate[g.operation.name()] += 1

        # The operation portion of the first byte (least significant bits).
        entry_op = bytearray([operations_supported.index(g.operation)])

        # Encode the first and (if applicable) second input wire indices.
        if len(g.wire_in_index) == 1:
            # Encode the input index as an offset from the output index.
            g.wire_in_index[0] = g.wire_out_index[0] - g.wire_in_index[0]

            # Collect the entries.
            (count_0, entries_0) = int_to_bytes_min(g.wire_in_index[0])

            # Encode the number of bytes in the entry in the first byte.
            entry_op[0] += count_0 * 8

            # Collect the data.
            data.extend(entry_op)
            data.extend(entries_0)
        else:
            # Encode input indices as offsets from the output index.
            g.wire_in_index[0] = g.wire_out_index[0] - g.wire_in_index[0]
            g.wire_in_index[1] = g.wire_out_index[0] - g.wire_in_index[1]

            # Collect the entries.
            (count_0, entries_0) = int_to_bytes_min(g.wire_in_index[0])
            (count_1, entries_1) = int_to_bytes_min(g.wire_in_index[1])

            # Track common patterns
            if tuple(g.wire_in_index) not in patterns:
                patterns[tuple(g.wire_in_index)] = 1
            else:
                patterns[tuple(g.wire_in_index)] += 1

            # Encode a common pattern in just one byte if it appears here.
            pattern_codes = [
                (1, 2), (2, 1), (4, 1), (64, 32),
                (593, 185), (591, 183), (183, 431), (185, 433),
                (595, 187), (187, 435), (1, 4), (183, 10671),
                (185, 10673), (187, 10675), (4, 5), (1, 303)
            ]
            if tuple(g.wire_in_index) in pattern_codes:
                entry_op[0] += 128 +\
                    (pattern_codes.index(tuple(g.wire_in_index)) * 8)
                entries_all = entry_op
            else:
                # Encode the number of bytes in the entry in the first byte.
                entry_op[0] += count_0 * 8
                entry_op[0] += count_1 * 8 * 4
                entries_all = entry_op + entries_0 + entries_1

            # Collect the data.
            data.extend(entries_all)

    # Show the number of each type of gate.
    print(" * gate frequencies: " + str(gate))

    # Display the top 16 patterns.
    print(" * top 16 pattern frequencies:")
    for (n,p) in list(reversed(sorted([(n, p) for (p, n) in patterns.items()])))[:16]:
        print("   - " + str(n) + ": " + str(p))

    # Show the effect of compression.
    out = compress(data, level=9)
    print(" * serialized representation of " + str(len(data)) + " bytes compressed to " + str(len(out)) + " bytes")

    # Collect buffer dimensions for various circuit components;
    # this allows CIGG to inform PIGG of the appropriate buffers
    # to allocate when PIGG calls CIGG.
    data_length = len(data) + 5*4
    return (data_length, bytes([c for cs in [
        # Length of the embedding itself, including these five values.
        data_length.to_bytes(4, 'big'),
        \
        # Length of SRGG representation for the labels for the first
        # input, the label pairs for the second input, and the label
        # pairs for the output.
        (1 + 4 + circuit.value_in_length[0]*(2+1*16)).to_bytes(4, 'big'),
        (1 + 4 + circuit.value_in_length[1]*(2+2*16)).to_bytes(4, 'big'),
        (1 + 4 + circuit.value_out_length[0]*(2+2*16)).to_bytes(4, 'big'),
        # Length of garbled gates SRGG buffer (using the counts of the
        # different types of gates).
        (
            1+4+((circuit.gate_count-gate['not'])*(2+(4*16))) + (gate['not']*2)
        ).to_bytes(4, 'big')
    ] for c in cs]) + data)

def embedded_inline_circuit_line_py(part, sep = "\n"):
    if isinstance(part, str):
        return part + sep
    else:
        return "    " + (",".join([str(a) for a in part])) + "," + sep

def embedded_inline_circuit_data_py(f_py, var_py, data, width, sep = "\n"):
    ps = list(parts(data, length=width))   
    (pre, post) = ("'''", "'''") if isinstance(data, str) else ("bytes([", "])")
    f_py.write("circuits.embedded['" + var_py + "'] = " + pre + sep)
    for p in tqdm(ps[:-1], desc = ' * writing gate data to Python file'):
        f_py.write(embedded_inline_circuit_line_py(p, sep))
    f_py.write(embedded_inline_circuit_line_py(ps[-1], sep) + post + "\n")

def embedded_inline_circuit(circuit, filename):
    # Mode for Python embedding: 'serialize_ints', 'serialize', or 'pickle'.
    mode_py = 'serialize'

    # Name of variable used for circuit data.
    name = filename.split("/")[-1]
    var = name.replace('-','_').replace('.h','')

    # Write the data to the files.
    with open(filename + '.h', 'w') as f_h:
        with open(filename + '.py', 'w') as f_py:
            # Line separator.
            sep = "\n"

            # Name of variable used for circuit data.
            var_h = filename.split("/")[-1].replace('-','_')
            var_py = filename.split("/")[-1]

            print()
            print('Generating serialized embedding for "' + var + '"...')
            (data_length, data) = serialize(circuit)

            # Write the declaration and circuit attributes to C++ header file.
            ps = list(parts(data, length=20))
            f_h.write("unsigned char EMBEDDED(" + var_h + "_embedded)[" + str(data_length) + "] = {" + sep)
            for p in tqdm(ps[:-1], desc = ' * writing gate data to C++ file'):
                f_h.write(",".join([str(a) for a in p]) + "," + sep)
            f_h.write(",".join([str(a) for a in ps[-1]]) + sep + "};\n")

            # Write the declaration and circuit attributes to Python source file.
            if mode_py == 'serialize_ints':
                # Explicit list of 8-bit integers with bytes wrapper.
                data = bytes([0]) + data
                embedded_inline_circuit_data_py(f_py, var_py, compress(data, level=9), 20, sep)
            else:
                if mode_py == 'serialize':
                    # Custom serialization scheme; 0 says data is serialized.
                    data = bytes([0]) + data
                elif mode_py == 'pickle':
                    # Base64 string from pickled data structure; 1 says data is pickled.
                    data = bytes([1]) + pickle.dumps(circuit)
                data_base64 = base64.standard_b64encode(compress(data, level=9)).decode('utf-8')
                embedded_inline_circuit_data_py(f_py, var_py, data_base64, 80, sep)

if __name__ == "__main__":
    print()

    # Create the destination directory if it does not exist.
    if not os.path.isdir('../circuit/embedded'):
        os.mkdir('../circuit/embedded')

    for (i, name) in enumerate([
        'aes-128-ecb-encrypt', 'aes-128-ecb-decrypt',
        'sha-256-for-lteq-440-bits', 'sha-256-for-lteq-952-bits'
    ]):
        embedded_inline_circuit(\
            circuit(open('../circuit/bristol/' + name + '.txt').read()),
            '../circuit/embedded/' + name
        )
