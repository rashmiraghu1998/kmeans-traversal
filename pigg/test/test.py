import sys
import os
import random
import parts
import bitlist
import nacl.utils
import nacl.secret
import hashlib
import flask
import time

sys.path.append("..") # To ensure import statements below work.

#
# Parse command line options.
#

(subject, service, options) = (None, None, tuple(sys.argv[1:]))
if options in [('library', 'server')]:
    (subject, service) = ('library', True)
elif options in [('pigg', 'server')]:
    (subject, service) = ('pigg', True)
elif options in [('library',)]:
    (subject, service) = ('library', False)
elif options in [('pigg',)]:
    (subject, service) = ('pigg', False)
elif options in [('huggs',)]:
    (subject, service) = ('huggs', True)
elif options in [('hugg',)]:
    (subject, service) = ('hugg', False)
elif __name__ == "__main__":
        print("\nInvalid command-line options; exiting.\n")
        exit()

#
# Load modules as determined by supplied options.
#

if subject == 'pigg':
    from module.pigg import *
elif subject == 'hugg':
    from module.hugg import hugg, circuits
    try:
        from module.hugg import hushc
    except:
        pass
elif subject == 'huggs':
    from module.huggs import huggs
    try:
        from module.huggs import hushs
    except:
        pass
else:
    from pigg.data.circuits import *
    from pigg.data.label import *
    from pigg.data.assignment import *
    from pigg.crypto.ot import *
    from pigg.core.garble import *
    from pigg.core.evaluate import *
    from pigg.core.server import *
    from pigg.core.client import *
    from pigg.core.cigg import *

#
# Functions used for testing.
#

def input_random(circuit):
    return [
        bitlist.bitlist([random.choice([0,1]) for _ in range(circuit.value_in_length[i])])
        for i in range(circuit.value_in_count)
    ]

def input_sha256_pad(bs):
    if len(bs) <= 440:
        return\
            bs+\
            bitlist.bitlist([1] + [0]*7 + [0]*((512-64-8)-len(bs)))+\
            bitlist.bitlist(len(bs), 16)
    elif len(bs) <=  952:
        return\
            bs+\
            bitlist.bitlist([1] + [0]*7 + [0]*((1024-64-8)-len(bs)))+\
            bitlist.bitlist(len(bs), 16)

def input_random_sha256_with_padding(circuit):
    # Build random SHA-256 input bit vector and padding (with length
    # encoding). Circuit expects 48 fewer bits because 6 of the 8 
    # length encoding bytes are never used for short inputs. Thus,
    # we review the two cases. Without optimization, we would have:
    # 
    #  * `variant` or `sum(circuit.value_in_length)` is 1024 or 512
    #  * length encoding is 64 bits
    #  * minimum 10...0 padding is 8 bits
    #  * maximum payload is `variant` - 64 - 8 bits
    #
    # With optimization, we have the following:
    #
    #  * `variant` is 1024 or 512
    #  * `sum(circuit.value_in_length)` is `variant` - 48
    #  * length encoding is 64 - 48 bits (two bytes is more than enough)
    #  * minimum 10...0 padding is 8 bits
    #  * maximum payload is `variant` - 64 - 8 bits
    #
    #  * maximum message payload is /var/ - (8 + (64-48));
    #  * maximum message payload without padding is /var/ - (64-48) - 8.

    variant = sum(circuit.value_in_length) + 48 # This is 512 or 1024.
    length_encoding_bitlen = 64 - 48
    payload_bitlen_max = variant - (length_encoding_bitlen+48) - 8
    payload_bitlen = 8 * random.randint(
        (8 if variant == 512 else 448) // 8, # At least 8; 0 not permitted.
        (440 if variant == 512 else 952) // 8
    )

    # Circuit input: data, 10...0 padding, and two-byte length encoding.
    bs = bitlist.bitlist([random.choice([0,1]) for _ in range(payload_bitlen)]) +\
         bitlist.bitlist([1] + [0]*7 + [0]*(payload_bitlen_max - payload_bitlen)) +\
         bitlist.bitlist(payload_bitlen, 64 - 48) # Two-byte encoding of length.

    return list(parts.parts(bs, length = circuit.value_in_length))

def aes_128_ecb_refs(key):
    def sbox(offset = 99):
        def rotl(x, k):
            return ((x << k) | (x >> (8 - k)))%256
        (sbox, (p, q)) = ([offset] + [None]*255, (1, 1))
        for i in range(255):
            p = p ^ ((p << 1)%256) ^ (27 if 0 != (p & 128) else 0)
            a = q ^ (q << 1)%256
            b = a ^ (a << 2)%256
            c = b ^ (b << 4)%256
            q = c ^ (9 if (c & 128) != 0 else 0)
            sbox[p] = (q^rotl(q, 1)^rotl(q, 2)^rotl(q, 3)^rotl(q, 4)) ^ offset
        return sbox

    def xor(xs, ys):
        return [x^y for (x,y) in zip(xs,ys)]

    def keys(key, S = sbox()):
        bss = list(parts.parts(key, 4))
        keys_for_rounds = [[v for v in bss]]
        round_const = [1, 2, 4, 8, 16, 32, 64, 128, 16+11, 48+6]
        for t in range(0, 10):
            bss[0] = [
                bss[0][0]^S[bss[3][1]]^round_const[t], bss[0][1]^S[bss[3][2]],
                bss[0][2]^S[bss[3][3]], bss[0][3]^S[bss[3][0]]
            ]
            bss[1] = xor(bss[1], bss[0])
            bss[2] = xor(bss[2], bss[1])
            bss[3] = xor(bss[3], bss[2])
            keys_for_rounds.append([b for b in bss])

        return keys_for_rounds

    def xtime(x, n = 1):
        return x if n==0 else xtime(((x<<1)%256)^((((x>>7)&1)*0x1b)%256), n-1)

    def aes128_ecb_crypt(krs, input, Sx, permute, mix):
        def add_keys(bss):
            return lambda kr: [[bss[i][j]^kr[i][j] for j in range(4)] for i in range(4)]
        bss = [xor(p, k) for (p,k) in zip(parts.parts(input, 4), krs[0])]
        for r in range(1, 11):
            bss = [[Sx[bss[i][j]] for j in range(4)] for i in range(4)] # Subtract bytes.
            bss = [[bss[p[j]][j] for j in range(4)] for p in permute] # Shift rows.
            bss = mix(bss, add_keys(krs[r])) if r < 10 else add_keys(krs[r])(bss)
        return bytes([n for ns in bss for n in ns])

    def aes128_ecb_encrypt(krs, plaintext):
        def mix(bss, add_keys_kr):
            return add_keys_kr([[ # Add keys last.
                bss[i][j] ^\
                (xtime(bss[i][j] ^ bss[i][(j+1)%4])) ^\
                (bss[i][0] ^ bss[i][1] ^ bss[i][2] ^ bss[i][3])
                for j in range(4)
            ] for i in range(4)])
        return aes128_ecb_crypt(krs, plaintext, sbox(), [[0,1,2,3],[1,2,3,0],[2,3,0,1],[3,0,1,2]], mix)

    def aes128_ecb_decrypt(krs, ciphertext):
        def xors_bytes(*xss):
            return xss[0] ^ xss[1] if len(xss) == 2 else xss[0] ^ xors_bytes(*xss[1:])
        def mul_gf28(x, y):
            return xors_bytes(*[(((y>>i) & 1) * xtime(x,i)) for i in range(5)])
        def mix_inv(bss, add_keys_kr):
            cs = [0x0e, 0x09, 0x0d, 0x0b]
            bss = add_keys_kr(bss) # Add keys first.
            return [[
                xors_bytes(*[mul_gf28(bs[j], cs[(i+4-j)%4]) for j in range(4)])
                for i in range(4)
            ] for bs in bss]
        sbox_inv = [i for (_,i) in sorted([(o,i) for (i,o) in enumerate(sbox())])]
        return aes128_ecb_crypt(list(reversed(krs)), ciphertext, sbox_inv, [[0,3,2,1],[1,0,3,2],[2,1,0,3],[3,2,1,0]], mix_inv)

    return {
        "aes-128-ecb-encrypt": (lambda val: aes128_ecb_encrypt(keys(key), val).hex()),
        "aes-128-ecb-decrypt": (lambda val: aes128_ecb_decrypt(keys(key), val).hex())
    }

def evaluate_reference(circuit_name, inputs):
    if circuit_name in [
        "sha-256-for-lteq-440-bits",
        "sha-256-for-lteq-952-bits"
    ]:
        # Remove padding and submit to the reference implementation.
        bits = bitlist.bitlist([b for bs in inputs for b in bs])
        message_length = int(bits[len(bits)-(64-48):]) # Two bytes (see above).
        bits = bits[0:message_length]
        return [bitlist.bitlist.fromhex(hashlib.sha256(bits.to_bytes()).hexdigest())]
    elif circuit_name in  ["aes-128-ecb-encrypt", "aes-128-ecb-decrypt"]:
        return [bitlist.bitlist.fromhex(
            aes_128_ecb_refs(inputs[1].to_bytes())\
                [circuit_name](inputs[0].to_bytes())
        )]
    else:
        return None

def measure(f):
    def f_new(*args):
        ts = time.time()
        result = f(*args)
        te = time.time()
        #print("Time to run: " + str(int((te - ts) * 1000)) + "ms")
        return result
    return f_new

def protocol_OT_simulation(_, input_g, input_e, wire_to_labels_g):
    # An alternative to the OT protocol (for testing).
    return {len(input_g)+i: [wire_to_labels_g[len(input_g)+i][input_e[i]]] for i in range(len(input_e))}

def protocol_OT_single(channel, input_g, input_e, wire_to_labels_g):
    # Two labels are sent by the garbler; the evaluator chooses
    # one via the OT protocol and its input bit.
    w_to_ls_e_input_two = {}
    for i in range(len(input_e)):
        # Share the garbler's public key.
        [garbler_key_secret, garbler_key_public] = ot.key_pair()
        channel['ot_sender_key'] = garbler_key_public

        # Send back evaluator's public key based on the bit.
        [evaluator_key_secret, evaluator_key_public] = ot.key_pair()
        channel['ot_receiver_message'] =\
            ot.receiver_send_message(channel['ot_sender_key'], evaluator_key_public, input_e[i])

        # Garbler sends the two labels.
        labels = wire_to_labels_g[i + len(input_g)]
        channel['ot_sender_response'] =\
            ot.sender_send_response(\
                garbler_key_secret, garbler_key_public,
                channel['ot_receiver_message'],
                labels[0].bytes(), labels[1].bytes()
            )

        # Evaluator determines label and updates wire-to-labels mapping.
        bytes = ot.receiver_receive_response(\
            garbler_key_public, evaluator_key_secret,
            channel['ot_sender_response'],
            input_e[i]
        )
        w_to_ls_e_input_two[len(input_g)+i] = [Label.from_bytes(bytes)]

    return w_to_ls_e_input_two

def protocol_OT_batch(channel, input_g, input_e, wire_to_labels_g):
    # Share the garbler's public keys.
    (garbler_keys_secret, garbler_keys_public) = ot.key_pairs(len(input_e))
    channel['ot_sender_keys'] = garbler_keys_public

    # Send back evaluator's public keys for each bit.
    (evaluator_keys_secret, evaluator_keys_public) = ot.key_pairs(len(input_e))
    channel['ot_receiver_messages'] =\
        ot.receiver_send_messages(channel['ot_sender_keys'], evaluator_keys_public, input_e)

    # Garbler sends the two labels for each bit.
    wire_in_two_to_labels = wire_to_labels_g[len(input_g):len(input_g)+len(input_e)]
    channel['ot_sender_responses'] =\
        ot.sender_send_responses(\
            garbler_keys_secret, garbler_keys_public,
            channel['ot_receiver_messages'],
            wire_in_two_to_labels
        )

    # Evaluator determines labels and updates wire-to-labels mapping.
    bytes_per_label =\
        ot.receiver_receive_responses(\
            garbler_keys_public, evaluator_keys_secret,
            channel['ot_sender_responses'],
            input_e
        )
    return Assignment([Label.from_bytes(bs)] for bs in bytes_per_label)

def protocol_pure_end_to_end(circuit, inputs):
    channel = {}

    if len(inputs) != 2:
        inputs = list(parts.parts([b for inp in inputs for b in inp], 2))

    (input_g, input_e) = inputs

    # Steps performed by garbler.
    wire_to_labels_g = garble.generate_wire_to_labels_map(circuit)
    gates_garbled_g = garble.garble_gates(circuit, wire_to_labels_g)
    channel["wire_in_to_label"] = garble.wire_in_to_label(wire_to_labels_g, input_g)
    channel["gates_garbled"] = gates_garbled_g

    # Steps performed by evaluator.
    w_to_ls_e = channel["wire_in_to_label"]
    gates_garbled_e = channel["gates_garbled"]

    # The below block is an interaction between both parties.
    w_to_ls_e_input_two = protocol_OT_batch(channel, input_g, input_e, wire_to_labels_g)

    # Steps performed by evaluator.
    w_to_ls_e.extend(w_to_ls_e_input_two)
    w_to_ls_e = evaluate.evaluate_gates(circuit, gates_garbled_e, w_to_ls_e)
    channel["wire_out_to_labels"] = w_to_ls_e.keep_only(circuit.wire_out_index)

    # Steps performed by garbler.
    wire_out_to_labels_g = channel["wire_out_to_labels"]
    bits = garble.output_labels_to_bits(wire_to_labels_g.keep_only(circuit.wire_out_index), wire_out_to_labels_g)

    return [bits]

def protocol_pure_stages(circuit, inputs):
    channel = {}

    if len(inputs) != 2:
        inputs = list(parts.parts([b for inp in inputs for b in inp], 2))

    (input_g, input_e) = inputs

    # Stage G.1.
    # Generate labels, garble gates, build wire mapping, and make OT keys.
    wire_to_labels_g = garble.generate_wire_to_labels_map(circuit)
    gates_garbled_g = garble.garble_gates(circuit, wire_to_labels_g)
    (garbler_keys_secret, garbler_keys_public) = ot.key_pairs(len(input_e))

    channel['ot_sender_keys'] = garbler_keys_public
    channel['wire_in_to_label'] = garble.wire_in_to_label(wire_to_labels_g, input_g)
    channel['gates_garbled'] = gates_garbled_g

    # Stage E.1.
    # Make OT keys, get garbled gates and wire mapping, and send OT messages.
    (evaluator_keys_secret, evaluator_keys_public) = ot.key_pairs(len(input_e))
    
    w_to_ls_e = channel["wire_in_to_label"]
    gates_garbled_e = channel["gates_garbled"]

    channel['ot_receiver_messages'] = [\
        ot.receiver_send_message(channel['ot_sender_keys'][i], evaluator_keys_public[i], input_e[i])
        for i in range(len(input_e))
    ]

    # Stage G.2.
    # Send OT responses.
    messages = channel['ot_receiver_messages']
    channel['ot_sender_responses'] = [\
        ot.sender_send_response(\
            garbler_keys_secret[i],
            garbler_keys_public[i],
            messages[i],
            wire_to_labels_g[i + len(input_g)][0].bytes(),
            wire_to_labels_g[i + len(input_g)][1].bytes()
        )
        for i in range(len(input_e))
    ]

    # Stage E.2.
    # Get labels based on OT, evaluate circuit, and send output labels.
    responses = channel['ot_sender_responses']
    for i in range(len(input_e)):
        bytes = ot.receiver_receive_response(\
            garbler_keys_public[i],
            evaluator_keys_secret[i],
            responses[i],
            input_e[i]
        )
        w_to_ls_e.append([Label.from_bytes(bytes)])
    w_to_ls_e = evaluate.evaluate_gates(circuit, gates_garbled_e, w_to_ls_e)
    channel["wire_out_to_labels"] = w_to_ls_e.keep_only(circuit.wire_out_index)

    # Stage G.3.
    # Decode output labels into an output bit vector.
    wire_out_to_labels_g = channel["wire_out_to_labels"]
    bits = garble.output_labels_to_bits(wire_to_labels_g.keep_only(circuit.wire_out_index), wire_out_to_labels_g)

    return [bits]

def protocol_client_server(
        circuit_name, inputs, 
        server_cigg=True, server_sodium=True,
        client_cigg=True, client_sodium=True
    ):
    # Split all the inputs into exactly two input bit vectors
    # (if there are not already exactly two input bit vectors).
    if len(inputs) != 2:
        inputs = bitlist.bitlist([b for bs in inputs for b in bs]) / 2
    (input_g, input_e) = inputs

    server_simulation = server(
        cigg=server_cigg, sodium=server_sodium,
        output=(lambda _, __, bytes_: bytes_), client_output=True
    )
    client_output = client(
            'http://localhost:5000/', simulated=server_simulation,
            cigg=client_cigg, sodium=client_sodium
        ).\
        compute(circuit_name, input_e, input_g)

    return [bitlist.bitlist(client_output)]

def circuit_embedded_random_inputs():
    circuit_names = [\
        "aes-128-ecb-encrypt", "aes-128-ecb-decrypt",
        "sha-256-for-lteq-440-bits", "sha-256-for-lteq-952-bits"
    ]

    print()
    print("Testing embedded circuits on random inputs:")
    for circuit_name in circuit_names:
        print("  * testing \"" + circuit_name + "\"...", end="")

        # Load circuit and assemble a random input for it.
        path = 'circuit/embedded/' + circuit_name + '.py'
        path = ('../'+path) if not os.path.exists(path) else path
        
        time_extraction_start = time.time()
        exec(open(path).read())
        c = circuits.load(circuit_name)
        time_extraction_end = time.time()
        time_str =\
            str(int((time_extraction_end - time_extraction_start) * 1000))+"ms"

        if circuit_name in ["sha-256-for-lteq-440-bits", "sha-256-for-lteq-952-bits"]:
            inputs = input_random_sha256_with_padding(c)
        else:
            inputs = input_random(c)

        out_reference = evaluate_reference(circuit_name, inputs)
        out_eval = list(map(bitlist.bitlist, c.evaluate(inputs)))

        if 1 == len(set([str(o[0]) for o in [\
            out_reference,
            out_eval
        ] if o is not None])):
            print("succeeded (extracted in " + time_str + ")", end="")
        else:
            print("failed:")
            print("      reference: " + str(out_reference[0].hex()))
            print("     evaluation: " + str(out_eval[0].hex()))
        print()

def circuit_all_random_inputs():
    circuit_names = [
        "logic-bristol-test", "logic-universal-1-bit",
        "logic-and-4-bit", "logic-and-8-bit",
        "arith-add-32-bit-old", "arith-add-64-bit-old",
        "arith-add-64-bit-truncated",
        "arith-sub-64-bit",
        "arith-mul-32-bit-old", "arith-mul-64-bit",
        "arith-mul-64-bit-truncated",
        "arith-div-64-bit",
        #"arith-neg-64-bit-with-eqw",
        "compare-eq-2-bit",
        "compare-eq-zero-64-bit",
        #"compare-eq-zero-128-bit-broken",
        "compare-lt-32-bit-signed-old", # Maybe sign is last bit.
        "compare-lt-32-bit-unsigned-old",
        "compare-lteq-32-bit-signed-old", # Maybe sign is last bit.
        "compare-lteq-32-bit-unsigned-old",
        "aes-128-ecb-encrypt", "aes-128-ecb-decrypt",
        "aes-128", "aes-128-non-expanded-old", "aes-128-expanded-old",
        "aes-192", "aes-256",
        "des-non-expanded-old", "des-expanded-old",
        "md5-old", "sha-1-old",
        "sha-256-for-lteq-440-bits", "sha-256-for-lteq-952-bits",
        "sha-256-for-eq-512-bits",
        "sha-256-new-partial", "sha-256-old", "sha-256-two-block",
        "sha-512",
        "keccak-f"
    ]

    print()
    print("Testing circuit files on random inputs:")
    for circuit_name in circuit_names:
        print("  * testing \"" + circuit_name + "\"...", end="")

        # Load circuit and assemble a random input for it.
        c = circuits.load(circuit_name)
        if circuit_name in ["sha-256-for-lteq-440-bits", "sha-256-for-lteq-952-bits"]:
            inputs = input_random_sha256_with_padding(c)
        else:
            inputs = input_random(c)

        # Dictionary containing outputs from various tests.
        out = {}
        
        # Reference (in-the-clear Python or system) implementation output.
        out_ref = evaluate_reference(circuit_name, inputs)
        if out_ref is not None:
            out['reference'] = out_ref

        # Circuit evaluation and non-server/client flow tests.
        out['evaluation'] = list(map(bitlist.bitlist, c.evaluate(inputs)))
        out['end-to-end'] = protocol_pure_end_to_end(c, inputs)
        out['in-stages'] = protocol_pure_stages(c, inputs)

        # Client-server simulations (not using CIGG).
        out_service_time = time.time()
        out['client(p)-server(p)'] = protocol_client_server(
            circuit_name, inputs, server_cigg=False, client_cigg=False
        )
        out_service_time = time.time() - out_service_time

        # Client-server simulations (using CIGG and CIGG/PIGG combinations).
        if cigg.lib is not None:
            out['client(c)-server(p)'] = protocol_client_server(
                circuit_name, inputs, server_cigg=True, client_cigg=False
            )
            out['client(p)-server(c)'] = protocol_client_server(
                circuit_name, inputs, server_cigg=False, client_cigg=True
            )
            out_service_time = time.time()
            out['client(c)-server(c)'] = protocol_client_server(
                circuit_name, inputs, server_cigg=True, client_cigg=True
            )
            out_service_time = time.time() - out_service_time

        # Display summary of results for the test ensemble for this circuit.
        if 1 == len(set(int(o[0]) for o in out.values())):
            print("succeeded (" + str(int(out_service_time * 1000)) + "ms)", end="")
        else:
            print("failed:")
            length = max([len(k) for k in out.keys()])
            for (key, val) in out.items():
                o = str(val[0]) if isinstance(val, list) and len(val) > 0 else "<error>"
                print("    - " + key.rjust(4+length, ".") + ": " + o)
        print()

def hugg_with_huggs(circuit_name, bytes_):
    h = hugg('http://localhost:5000/')
    if circuit_name == 'aes-128-ecb-encrypt':
        return h.aes128_ecb_encrypt(val = bytes_)
    elif circuit_name == 'aes-128-ecb-decrypt':
        return h.aes128_ecb_decrypt(val = bytes_)
    elif circuit_name in ['sha-256-for-lteq-440-bits', 'sha-256-for-lteq-952-bits']:
        return h.sha256(val = bytes_)

def hugg_client_random_inputs(huggs_func_in):
    circuit_names = [\
        "aes-128-ecb-encrypt", "aes-128-ecb-decrypt",
        "sha-256-for-lteq-440-bits", "sha-256-for-lteq-952-bits"
    ]

    # Run HUSH test if it has been merged into HUGG module.
    constructor = hugg
    try:
        constructor = hushc
    except:
        pass
    h = constructor('http://localhost:5000/')
    if hasattr(h, 'hush') and not isinstance(h.hush, str):
        print()
        print("Testing HUGG client and server HUSH capability:")
        for _ in range(2):
            print(h.hush(bytes([123]*16)).hex())

    print()
    print("Testing HUGG client and server on random inputs:")
    for circuit_name in circuit_names:
        print("  * testing \"" + circuit_name + "\"...", end="")

        # Load circuit and assemble a random input for it.
        c = circuits.load(circuit_name)
        if circuit_name == "sha-256-for-lteq-440-bits":
            bs = bitlist.bitlist([random.choice([0,1]) for _ in range(128)])
            bs_ = input_sha256_pad(bitlist.bitlist(huggs_func_in(None, hugg.constant.sha256, None, None)) + bs)
            out_reference = evaluate_reference(circuit_name, [bs_])[0]
            out_service = bitlist.bitlist(hugg_with_huggs(circuit_name, bs.to_bytes()))
        elif circuit_name == "sha-256-for-lteq-952-bits":
            bs = bitlist.bitlist([random.choice([0,1]) for _ in range(512)])
            bs_ = input_sha256_pad(bitlist.bitlist(huggs_func_in(None, hugg.constant.sha256, None, None)) + bs)
            out_reference = evaluate_reference(circuit_name, [bs_])[0]
            out_service = bitlist.bitlist(hugg_with_huggs(circuit_name, bs.to_bytes()))
        else:
            (bs_k, bs_v) = (
                bitlist.bitlist(huggs_func_in(None, None, None, None)),
                bitlist.bitlist([random.choice([0,1]) for _ in range(128)])
            )
            out_reference = evaluate_reference(circuit_name, [bs_k, bs_v])[0]
            out_service = bitlist.bitlist(hugg_with_huggs(circuit_name, bs_v.to_bytes()))

        if 1 == len(set([str(o) for o in [out_reference, out_service]])):
            print("succeeded", end="")
        else:
            print("failed:")
            print("      reference: " + str(out_reference.hex()))
            print("  client-server: " + str(out_service.hex()))
        print()

if __name__ == "__main__":
    if subject in ['library', 'pigg']:
        if service:
            server_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
            server(
                key = lambda _: server_key
            ).route(flask.Flask(__name__)).run(debug=True)
        else:
            circuit_embedded_random_inputs()
            circuit_all_random_inputs()
            print()
    elif subject in ['huggs', 'hugg']:
        # Function that generates server input portions.
        try:    hugg_sha256 = hugg.constant.sha256
        except: hugg_sha256 = huggs.constant.sha256
        def huggs_func_in(server, function, length, meta):
            if function == hugg_sha256:
                return bitlist.bitlist([0]*5*8).to_bytes()
            else:
                return bitlist.bitlist([0]*128).to_bytes()

        if subject == 'huggs':
            server_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
            
            # Use HUSH wrapper if it has been merged into HUGG server module.
            constructor = huggs
            try:
                constructor = hushs
            except:
                pass
            server = constructor(
                server_input_lengths = {'sha256':5, '*':16},
                client_output=True
            )

            @server.key
            def huggs_func_key_example(server):
                return server_key

            @server.input
            def huggs_func_in_example(server, function, length, meta):
                return huggs_func_in(server, function, length, meta)

            @server.output
            def huggs_func_out_example(server, function, result):
                print("\nHUGGS output: " + result.hex() + "\n")
                return result

            server.route(flask.Flask(__name__)).run(debug=True)
        elif subject == 'hugg':
            hugg_client_random_inputs(huggs_func_in)
