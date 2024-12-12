from bitlist import bitlist
from circuit import *
from circuitry import *

from arithmetic import *

#
# Standard MD5 circuit functions and helpers.
#

def b2l(xs):  # Big-endian to little-endian order in BYTES only
    return [b for bs in list(reversed(list(bits(xs)/{8}))) for b in bs]

def rotl(xs, y):
    return xs[y:]+xs[:y]

def md5_pad(m):
    lm = len(m)
    lmb = (lm*8).to_bytes(8, byteorder='little')
    lp = (55-lm) % 64
    return [b for b in m] + [128] + [0]*lp + [b for b in lmb]

def sin32(x):
    from math import sin
    return int(pow(2, 32) * abs(sin(x)))

def round_f(j):
    if j < 16:
        return ((lambda b, c, d: (b & c) | (~b & d)), j, [7,12,17,22][j%4])  # -OR- lambda b, c, d: d ^ (b & (c ^ d))
    elif j < 32:
        return ((lambda b, c, d: (d & b) | (~d & c)), (5 * j + 1) % 16, [5,9,14,20][j%4])  # -OR- lambda b, c, d: c ^ (d & (b ^ c))
    elif j < 48:
        return ((lambda b, c, d: b ^ c ^ d), (3 * j + 5) % 16, [4,11,16,23][j%4])
    elif j < 64:
        return ((lambda b, c, d: c ^ (b | ~d)), (7 * j) % 16, [6,10,15,21][j%4])

def md5(message):
    K = list(map(constants, [to_bits(sin32(x)) for x in range(1, 65)]))  # Sixty-four 32-element bit vectors.
    digest = list(map(constants, [ # Four 32-element bit vectors.
        [0,1,1,0,0,1,1,1,0,1,0,0,0,1,0,1,0,0,1,0,0,0,1,1,0,0,0,0,0,0,0,1],
        [1,1,1,0,1,1,1,1,1,1,0,0,1,1,0,1,1,0,1,0,1,0,1,1,1,0,0,0,1,0,0,1],
        [1,0,0,1,1,0,0,0,1,0,1,1,1,0,1,0,1,1,0,1,1,1,0,0,1,1,1,1,1,1,1,0],
        [0,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,1,0,1,0,1,0,0,0,1,1,1,0,1,1,0]
    ]))

    for i in range(0, len(message), 512):
        (a, b, c, d) = digest
        chunk = message[i:i+512]
        for j in range(64):  # Loop over each of the 64 byte-partitions in a 512-bit block
            F, g, s = round_f(j)
            f = F(b, c, d)
            f = add32(
                add32(a, f),
                add32(K[j], b2l(chunk[g*32:(g+1)*32]))
            )
            (a, b, c, d) = (d, add32(b, rotl(f, s)), b, c)
        digest = list(map(unzip(add32), zip(digest, (a, b, c, d))))

    return bytes(map(int, bits([output(b) for word in digest for b in b2l(word)])/{8})).hex()

def synthesize_emit_test_md5_variant(
        feedback, emit_file_and_check,
        path, function, sig, input_test, output_target
    ):
    name = path.split("/")[-1]
    print()
    bit.circuit(circuit())
    input_test = md5_pad(input_test.encode('ascii'))
    output_test = function([b for i8 in input_test for b in bits.from_byte(i8, input)])
    circ = bit.circuit()
    print("Synthesized `" + name + "` with " + str(len(circ.gate)) + " gates:")
    print(' * operation counts: ', {
        o.name(): circ.count(lambda g: g.operation == o)
        for o in [op.not_, op.and_, op.xor_, op.or_, op.nand_, op.nif_, op.id_, op.xnor_, op.nimp_]
    })
    feedback(name, "direct evaluation during synthesis", output_test, output_target)
    input_test = [
        b
        for i8 in input_test
        for b in bits.from_byte(i8, lambda b: b)
    ]
    feedback(
        name, "data structure evaluated on input",
        bitlist(circ.evaluate(input_test)).hex(), output_target
    )
    circ.signature = sig
    emit_file_and_check(path, circ, input_test, output_target)
