import sys
from itertools import product
from functools import reduce
from tqdm import tqdm
from parts import parts
from flats import flats
from bitlist import bitlist
from bfcl import circuit as bristol_fashion
from circuit import *
from circuitry import *

sys.path.append("synth/") # To ensure import statements below work.

from arithmetic import *
from sha256 import *
from aes128 import *
from md5 import *

#
# Optimizations that eliminate constant gates from the circuit.
#

cache = {}
def bit_cache(o, v, *args):
    """
    Optimization that reuses gate outputs when possible.
    Note that `cache` must be reset between each synthesis job.
    """
    if o in [op.and_, op.xor_, op.or_, op.nand_, op.xnor_]:
        (a1, a2) = args
        key = (o, frozenset({a1.gate.index, a2.gate.index}))
        if not key in cache:
            result = bit_optimize(o, v, *args)
            cache[key] = result
            return result
        else:
            return cache[key]
    else:
        return bit_optimize(o, v, *args)

def bit_optimize(o, v, *args):
    """
    Optimization that collapses gates when they have constants
    as inputs.
    """
    if o.arity() == 2:
        (a1, a2) = args
        if type(a1) is constant and type(a2) is constant:
            return constant(v)
        elif o == op.and_:
            if type(a1) is constant and type(a2) is not constant:
                return a2 if a1.value == 1 else constant(0)
            elif type(a1) is not constant and type(a2) is constant:
                return a1 if a2.value == 1 else constant(0)
        elif o == op.xor_:
            if a1.gate.index == a2.gate.index:
                return constant(0)
            elif type(a1) is constant and type(a2) is not constant:
                if a1.value == 0:
                    return a2
                else:
                    return bit(1 - a2.value, bit.gate(op.not_, [a2.gate]))
            elif type(a1) is not constant and type(a2) is constant:
                if a2.value == 0:
                    return a1
                else:
                    return bit(1 - a1.value, bit.gate(op.not_, [a1.gate]))
        elif o == op.or_:
            if type(a1) is constant and type(a2) is not constant:
                return constant(1) if a1.value == 1 else a2
            elif type(a1) is not constant and type(a2) is constant:
                return constant(1) if a2.value == 1 else a1
        elif o == op.nand_:
            if type(a1) is constant and type(a2) is not constant:
                return constant(1) if a1.value == 0 else ~a2
            elif type(a1) is not constant and type(a2) is constant:
                return constant(1) if a2.value == 0 else ~a1
        elif o == op.nimp_:
            if type(a1) is constant and type(a2) is not constant:
                return constant(0) if a1.value == 0 else ~a2
            elif type(a1) is not constant and type(a2) is constant:
                return a1 if a2.value == 0 else constant(0)
        elif o == op.nif_:
            if type(a1) is constant and type(a2) is not constant:
                return a2 if a1.value == 0 else constant(0)
            elif type(a1) is not constant and type(a2) is constant:
                return constant(0) if a2.value == 0 else ~a1
        elif o == op.xnor_:
            if type(a1) is constant and type(a2) is not constant:
                return a2 if a1.value == 1 else ~a2
            elif type(a1) is not constant and type(a2) is constant:
                return a1 if a2.value == 1 else ~a1
    else:
        (a1,) = args
        if type(a1) is constant:
            return constant(v)

bit.hook_operation(bit_optimize)

#
# Reusable utility functions.
#

def int_to_bits(x, l):
    return list(reversed([(x >> i) % 2 for i in range(l)]))

def str_if_not(o):
    return o if type(o) == str else str(o)

def feedback(name, desc, output_test, output_target):
    # Synchronize types of output test result and target.
    if type(output_target) == list: # List of integers from (0,1).
        output_target = bitlist(output_target)

    if type(output_test) == list: # List of integers from (0,1).
        output_test = bitlist(output_test)

    if type(output_target) == str: # Hexadecimal representation in string format.
        if type(output_test) == bitlist:
            output_test = output_test.hex()       

    # Check the test output against the target and display feedback.
    if output_test == output_target:
        print(" * circuit " + desc + " for `" + name + "` has correct output")
    else:
        print(" * circuit " + desc + " for `" + name + "` has incorrect output")
        print("   -  received: " + str_if_not(output_test) + "")
        print("   -  expected: " + str_if_not(output_target) + "")

def emit_file_and_check(path, circ, input_test, output_target):
    name = path.split("/")[-1]
    with open(path, 'w') as circuit_file:
        # Build and emit the Bristol Fashion circuit file.
        circuit_file.write(bristol_fashion(circ).emit(
            progress=lambda gs: tqdm(gs, desc=' * emitting circuit file')
        ))

    # Parse and test the circuit file after it has been written and closed.
    circ = bristol_fashion(open(path).read())
    output_test = circ.evaluate(list(parts(input_test, length=512)))[0]
    feedback(name, "parsed from emitted circuit file", output_test, output_target)

#
# Synthesis functions for specific circuits.
#

if __name__ == '__main__':

    if 'sha-256' in sys.argv:
        synthesize_emit_test_sha256_variant(
            feedback, emit_file_and_check,
            "../circuit/bristol/sha-256-for-lteq-440-bits.txt",
            sha256, signature([128, 336], [256]),
            ([51, 51]) + ([128]+[0]*53) + \
                # [0]*6 + # Part of length encoding; constants.
                [0, 16],
            "c6f3ac57944a531490cd39902d0f777715fd005efac9a30622d5f5205e7f6894"
        )
        synthesize_emit_test_sha256_variant(
            feedback, emit_file_and_check,
            "../circuit/bristol/sha-256-for-lteq-952-bits.txt",
            sha256, signature([128, 848], [256]),
            ([51]*64+ [51]*55) + ([128] + [0]*0) +
                # [0]*6 + # Part of length encoding; constants.
                [3, 184],
            "d60e4019e46dc24db1e01646062b89cd01812d448c3729b3aa375141a6793ef0"
        )

    if 'md5' in sys.argv:
        synthesize_emit_test_md5_variant(
            feedback, emit_file_and_check,
            "../circuit/bristol/md5-lteq-440-bits.txt",
            md5, signature([512], [128]),
            "The quick brown fox jumps over the lazy dog.",  # 352 bits
            "e4d909c290d0fb1ca068ffaddf22cbd0"
        )

    if 'md5' in sys.argv:
        synthesize_emit_test_md5_variant(
            feedback, emit_file_and_check,
            "../circuit/bristol/md5-lteq-952-bits.txt",
            md5, signature([1024], [128]),
            "The quick brown fox jumps over the lazy dog's back 1234567890",  # 488 bits
            "bb3f80dde4572a2d3f1e9d2c9b9c809b"
        )

    if 'md5' in sys.argv:
        synthesize_emit_test_md5_variant(
            feedback, emit_file_and_check,
            "../circuit/bristol/md5-lteq-1464-bits.txt",
            md5, signature([1536], [128]),
            "The quick brown fox jumps over the lazy dog's back.  Pack my box with " +
            "five dozen liquor jugs.  Amazingly few discotheques provide jukeboxes.",  # 1120 bits
            "51f36dae5f8e993773cada182d869f36"
        )


    if 'aes-128' in sys.argv:
        synthesize_emit_test_aes128_direction(
            feedback, emit_file_and_check,
            "../circuit/bristol/aes-128-ecb-encrypt.txt",
            aes128_ecb_crypt, signature([128, 128], [128]),
            [123,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] +\
                [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "6ce708def92ddfc9ce13d8621262a268"
        )
        synthesize_emit_test_aes128_direction(
            feedback, emit_file_and_check,
            "../circuit/bristol/aes-128-ecb-decrypt.txt",
            (lambda mnk: aes128_ecb_crypt(mnk, True)), signature([128, 128], [128]),
            [n for n in bytearray.fromhex("6ce708def92ddfc9ce13d8621262a268")]+\
                [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "7b000000000000000000000000000000"
        )

    # add-
    for l in [int(arg[4:]) for arg in sys.argv if arg.startswith("add-")]:
        synthesize_emit_test_arith(
            feedback, emit_file_and_check,
            "../circuit/bristol/arith-add-{}-bit.txt".format(l),
            add, signature([l, l], [l]),
            int_to_bits(15, l) +\
            int_to_bits(33, l),
            int_to_bits(48, l)
        )

    # sub-
    for l in [int(arg[4:]) for arg in sys.argv if arg.startswith("sub-")]:
        synthesize_emit_test_arith(
            feedback, emit_file_and_check,
            "../circuit/bristol/arith-sub-{}-bit.txt".format(l),
            sub, signature([l, l], [l]),
            int_to_bits(48, l) +\
            int_to_bits(33, l),
            int_to_bits(15, l)
        )

    # mul-
    for l in [int(arg[4:]) for arg in sys.argv if arg.startswith("mul-")]:
        synthesize_emit_test_arith(
            feedback, emit_file_and_check,
            "../circuit/bristol/arith-mul-{}-bit.txt".format(l),
            mul, signature([l, l], [l]),
            int_to_bits(7, l) +\
            int_to_bits(12, l),
            int_to_bits(84, l)
        )

    if 'div-8' in sys.argv:
        synthesize_emit_test_arith(
            feedback, emit_file_and_check,
            "../circuit/bristol/arith-div-8-bit.txt",
            div, signature([8, 8], [8]),
            [0,0,0,1,1,1,0,0] +\
            [0,0,0,0,1,1,1,0],
            int_to_bits(2, 8)#[0,0,0,0,0,0,0,1]
        )

    if 'div-32' in sys.argv:
        synthesize_emit_test_arith(
            feedback, emit_file_and_check,
            "../circuit/bristol/arith-div-32-bit.txt",
            div, signature([32, 32], [32]),
            int_to_bits(84, 32) +\
            int_to_bits(12, 32),
            int_to_bits(7, 32)
        )

    if 'div-64' in sys.argv:
        synthesize_emit_test_arith(
            feedback, emit_file_and_check,
            "../circuit/bristol/arith-div-64-bit.txt",
            div, signature([64, 64], [64]),
            int_to_bits(84, 64) +\
            int_to_bits(12, 64),
            int_to_bits(7, 64)
        )

    # gteq-
    for l in [int(arg[5:]) for arg in sys.argv if arg.startswith("gteq-")]:
        synthesize_emit_test_arith(
            feedback, emit_file_and_check,
            "../circuit/bristol/compare-gteq-{}-bit.txt".format(l),
            gteq, signature([l, l], [1]),
            int_to_bits(5, l) +\
            int_to_bits(4, l),
            int_to_bits(1, 1)
        )

    # max-
    for l in [int(arg[4:]) for arg in sys.argv if arg.startswith("max-")]:
        synthesize_emit_test_arith(
            feedback, emit_file_and_check,
            "../circuit/bristol/arith-max-{}-bit.txt".format(l),
            max, signature([l, l], [l]),
            int_to_bits(5, l) +\
            int_to_bits(4, l),
            int_to_bits(5, l)
        )

    # eq-
    for l in [int(arg[3:]) for arg in sys.argv if arg.startswith("eq-")]:
        synthesize_emit_test_arith(
            feedback, emit_file_and_check,
            "../circuit/bristol/compare-eq-{}-bit.txt".format(l),
            eq, signature([l, l], [1]),
            int_to_bits(5, l) +\
            int_to_bits(5, l),
            int_to_bits(1, 1)
        )

    # neq-
    for l in [int(arg[4:]) for arg in sys.argv if arg.startswith("neq-")]:
        synthesize_emit_test_arith(
            feedback, emit_file_and_check,
            "../circuit/bristol/compare-neq-{}-bit.txt".format(l),
            neq, signature([l, l], [1]),
            int_to_bits(5, l) +\
            int_to_bits(5, l),
            int_to_bits(0, 1)
        )

    # gt-
    for l in [int(arg[3:]) for arg in sys.argv if arg.startswith("gt-")]:
        synthesize_emit_test_arith(
            feedback, emit_file_and_check,
            "../circuit/bristol/compare-gt-{}-bit.txt".format(l),
            gt, signature([l, l], [1]),
            int_to_bits(5, l) +\
            int_to_bits(4, l),
            int_to_bits(1, 1)
        )
