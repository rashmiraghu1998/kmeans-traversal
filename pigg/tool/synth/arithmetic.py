from circuit import *
from circuitry import *
def and_bit(x, y): return x.and_(y)  # AND
def lor_bit(x, y): return x.or_(y)   # LOR
def xor_bit(x, y): return x.xor_(y)  # XOR
def if_else(c, x, y): return xor_bit(and_bit(c, x), and_bit(~c, y))

#
# Reusable utility functions.
#

def rev(xs):
    return list(reversed(xs))

def to_bits(n):
    return list(map(int, format(n, 'b').zfill(32)))

def bind_length(f, length):
    return lambda *a, **kw: f(l=length, *a, **kw)

def unzip(f):
    return lambda params : f(*params)

def treduce(op, arr):  # structure a series of operations into a balanced tree (useful when commutative+associative) and evaluate
    j = len(arr)//2  # middle index
    return op(treduce(op, arr[:j]), treduce(op, arr[j:])) if j>0 else arr[0]

def check_lengths(xs, ys, l):
    if (not l == None) and ((not len(xs) == l) or (not len(xs) == len(ys))):
        raise RuntimeError('arithmetic failed: xs and ys must both be %d bits long.' % l)

def pad(xs, l):
    lx = len(xs)
    lp = l - lx
    ps = constants([0]*lp)  # QUESTION: Is this any better than doing constants([0])*lp
    return xs + ps

#
# A high level combinator for iteration of bit arrays
#

def bit_combinator(xs, ys, f, z0, temp0, keep_temp_bit=False):
    from functools import reduce
    def combine(zs, xy):
        (x, y) = xy
        temp_in = zs.pop()
        [z, temp_out] = f(x, y, temp_in)
        return zs + [z] + [temp_out]
    zs = reduce(combine, zip(xs, ys), [temp0])
    if not keep_temp_bit: zs.pop()
    return [z0] + zs

#
# Primitive arithmetic functions.
#

def bit_adder(x, y, carry):
    _xor = xor_bit(x, y)

    # save and update carry
    _sum = xor_bit(_xor, carry)
    carry = lor_bit(
        and_bit(x, y),
        and_bit(_xor, carry)
    )

    return [_sum, carry]

def bit_subtractor(x, y, borrow):
    _xor = xor_bit(x, y)

    # save and update borrow
    diff = xor_bit(_xor, borrow)
    borrow = lor_bit(
        and_bit(~x, y),
        and_bit(~_xor, borrow)
    )

    return [diff, borrow]

def add(xs, ys, l, preserve_overflow_bit=False):
    check_lengths(xs, ys, l)
    (xs, ys) = (list(reversed(xs)), list(reversed(ys)))

    # Match head and tail
    (x0, xt) = (xs[0], xs[1:])
    (y0, yt) = (ys[0], ys[1:])

    # The first sum bit and carry bit are computed quicker as:
    (sum0, carry0) = (xor_bit(x0, y0), and_bit(x0, y0))

    # Create a ripple-carry adder and with it, sum the remaining bits
    zs = bit_combinator(xt, yt, bit_adder, sum0, carry0, keep_temp_bit=preserve_overflow_bit)

    return bits(list(reversed(zs)))

def sub(xs, ys, l, preserve_overflow_bit=False):
    check_lengths(xs, ys, l)
    (xs, ys) = (list(reversed(xs)), list(reversed(ys)))

    # Match head and tail
    (x0, xt) = (xs[0], xs[1:])
    (y0, yt) = (ys[0], ys[1:])

    # The first difference bit and carry bit are computed quicker as:
    (diff0, borrow0) = (xor_bit(x0, y0), and_bit(~x0, y0))

    # Process the remaining bits through a ripple-borrow subtractor
    zs = bit_combinator(xt, yt, bit_subtractor, diff0, borrow0, keep_temp_bit=preserve_overflow_bit)

    # if preserve_overflow_bit:
    #     overflow_bit = zs.pop()

    return bits(list(reversed(zs)))

def mul(xs, ys, l):
    check_lengths(xs, ys, l)
    partial_products = [(xs << i) & bits([ys[l-i-1]]*l) for i in range(0,l)]
    zs = treduce(bind_length(add, l), partial_products)
    return zs

def long_div(xs, ys, l):
    check_lengths(xs, ys, l)
    (xs, ys) = (list(reversed(xs)), list(reversed(ys)))

    quotient = [None]*l
    remainder = constants([0]*(l-1))  # or constants([0])*(l-1) ?

    for i, x in reversed(list(enumerate(xs))):  # range(len(xs)-1,-1,-1); x = xs[i]

        # Add bit i to the head of remainder (least significant bit)
        remainder = [x] + remainder[0:l-1]

        # Get the next bit of the quotient
        # and conditionally subtract b from the
        # intermediate remainder to continue
        diff = rev(sub(rev(remainder), rev(ys), l, preserve_overflow_bit=True))
        noUnderflow = ~diff.pop()  # get the overflow bit, diff is now the result of subtraction

        # Get next bit of quotient
        quotient[i] = noUnderflow  # and_bit(noUnderflow, noUnderflow)

        # Update remainder
        for (j, _) in enumerate(remainder):
            # note, if noUnderflow, then |# bits in diff| <= |# bits in remainder|
            remainder[j] = if_else(noUnderflow, diff[j], remainder[j])

    return (rev(quotient), rev(remainder))

def div(xs, ys, l):
    (quotient, _) = long_div(xs, ys, l)
    return quotient

def mod(xs, ys, l):
    (_, remainder) = long_div(xs, ys, l)
    return remainder

def lteqb(xs, ys, l):
    return sub(xs, ys, l, preserve_overflow_bit=True)[0]

def gteqb(xs, ys, l):
    return ~lteqb(xs, ys, l)

def lteq(xs, ys, l):
    return [lteqb(xs, ys, l)]  # because the output must be a bit array

def gteq(xs, ys, l):
    return [gteqb(xs, ys, l)]  # because the output must be a bit array

def min(xs, ys, l):
    lte = lteqb(xs, ys, l)
    return [if_else(lte, x, y) for x, y in zip(xs, ys)]

def max(xs, ys, l):
    lte = lteqb(xs, ys, l)
    return [if_else(lte, y, x) for x, y in zip(xs, ys)]

def eqb(xs, ys, l):
    _xnor = [~xor_bit(x, y) for (x, y) in zip(xs, ys)]
    return treduce(and_bit, _xnor)

def neqb(xs, ys, l):
    return ~eqb(xs, ys, l)

def eq(xs, ys, l):
    return [eqb(xs, ys, l)]  # because the output must be a bit array

def neq(xs, ys, l):
    return [neqb(xs, ys, l)]  # because the output must be a bit array

def ltb(xs, ys, l):
    return ~gteqb(xs, ys, l)

def gtb(xs, ys, l):
    return ~lteqb(xs, ys, l)

def lt(xs, ys, l):
    return [ltb(xs, ys, l)]  # because the output must be a bit array

def gt(xs, ys, l):
    return [gtb(xs, ys, l)]  # because the output must be a bit array

#
# Exports
#

def add8(xs, ys): return add(xs, ys, 8)
def add32(xs, ys): return add(xs, ys, 32)

def sub8(xs, ys): return sub(xs, ys, 8)
def sub32(xs, ys): return sub(xs, ys, 32)

def mul8(xs, ys): return mul(xs, ys, 8)
def mul32(xs, ys): return mul(xs, ys, 32)

def mul8(xs, ys): return mul(xs, ys, 8)
def mul32(xs, ys): return mul(xs, ys, 32)

def div8(xs, ys): return div(xs, ys, 8)
def div32(xs, ys): return div(xs, ys, 32)
def div64(xs, ys): return div(xs, ys, 64)

def mod8(xs, ys): return mod(xs, ys, 8)
def mod32(xs, ys): return mod(xs, ys, 32)

def lteq32(xs, ys): return lteq(xs, ys, 32)
def gteq32(xs, ys): return gteq(xs, ys, 32)

def min32(xs, ys): return min(xs, ys, 32)
def max32(xs, ys): return max(xs, ys, 32)

def eq32(xs, ys): return eq(xs, ys, 32)
def neq32(xs, ys): return neq(xs, ys, 32)

def lt32(xs, ys): return lt(xs, ys, 32)
def gt32(xs, ys): return gt(xs, ys, 32)

def synthesize_emit_test_arith(
        feedback, emit_file_and_check,
        path, function, sig, input_test, output_target
):
    name = path.split("/")[-1]
    print()
    bit.circuit(circuit())
    (xl, yl, zl) = sig.input_format + sig.output_format
    (xs, ys) = (bits([input_one(i) for i in input_test[0:xl]]), bits([input_two(i) for i in input_test[xl:xl+yl]]) )
    zs = function(xs, ys, l=xl)
    output_test = [int(output(b)) for b in zs]
    circ = bit.circuit()
    print("Synthesized `" + name + "` with " + str(len(circ.gate)) + " gates:")
    print(' * operation counts: ', {
        o.name(): circ.count(lambda g: g.operation == o)
        for o in [op.not_, op.and_, op.xor_, op.or_, op.nand_, op.nif_, op.id_, op.xnor_, op.nimp_]
    })
    feedback(name, "direct evaluation during synthesis", output_test, output_target)
    feedback(
        name, "data structure evaluated on input",
        circ.evaluate(input_test), output_target
    )
    circ.signature = sig
    emit_file_and_check(path, circ, input_test, output_target)
