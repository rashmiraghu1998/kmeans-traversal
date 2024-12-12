from sys import path
from random import getrandbits
path.append("..")  # To ensure import statements below work.
from pigg.core.client import *
from test import input_random, protocol_client_server

l = 32  # of bits
m = pow(2, l)
to_bits = lambda n : bitlist.bitlist(format(n, 'b').zfill(l))

N = 20  # of trials
op_sign = "÷"
op_name = "div"
op = lambda a, b : a // b

for i in range(N):
    a = getrandbits(l)
    b = getrandbits(l)
    inputs = list(map(to_bits, [a, b]))

    a_op_b = op(a, b) % m
    output = protocol_client_server("arith-{}-{}-bit".format(op_name, l), inputs, server_cigg=False, client_cigg=False)

    if to_bits(a_op_b) in output:
        print("({}/{})\t ({} {} {}) mod {} = {}".format(i, N, a, op_sign, b, m, a_op_b))  # pass
    else:
        raise Exception("Circuit returned an unexpected output: ({} {} {}) mod {} ≠ {}".format(a, op_sign, b, m, a_op_b))