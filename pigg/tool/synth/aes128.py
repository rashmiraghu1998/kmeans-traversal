from parts import parts
from flats import flats
from bitlist import bitlist
from circuit import *
from circuitry import *

from arithmetic import *

#
# Standard AES-128 ECB circuit functions and helpers.
#

def aes128_ecb_sbox_opt(xs):
    (x0,x1,x2,x3,x4,x5,x6,x7) = xs
    x8 = (x3 ^ x0)
    x9 = (x6 ^ x0)
    x10 = (x5 ^ x3)
    x11 = (x1 ^ x2)
    x12 = (x8 ^ x4)
    x13 = (~(x12))
    x14 = (x6 == x13)
    x15 = (x4 == x6)
    x16 = (x15 ^ x1)
    x17 = (~(x16))
    x18 = (x17 ^ x5)
    x19 = (x1 == x7)
    x20 = (x2 == x19)
    x21 = (x4 & x6)
    x22 = (~(x4))
    x23 = (~(x6))
    x24 = (x22 & x23)
    x25 = (x21 | x24)
    x26 = (x5 == x25)
    x27 = (x26 ^ x2)
    x28 = (x7 ^ x11)
    x29 = (~(x28))
    x30 = (x3 == x29)
    x31 = (x11 & x7)
    x32 = (~(x11))
    x33 = (~(x7))
    x34 = (x32 & x33)
    x35 = (x31 | x34)
    x36 = (x6 == x35)
    x37 = (x5 & x2)
    x38 = (~(x5))
    x39 = (~(x2))
    x40 = (x38 & x39)
    x41 = (x37 | x40)
    x42 = (x8 == x41)
    x43 = (x6 & x8)
    x44 = (~(x6))
    x45 = (~(x8))
    x46 = (x44 & x45)
    x47 = (x43 | x46)
    x48 = (x4 == x47)
    x49 = (x11 ^ x48)
    x50 = (x7 == x27)
    x51 = (x11 == x50)
    x52 = (~(x3))
    x53 = (x0 > x30)
    x54 = (x0 < x30)
    x55 = (x53 | x54)
    x56 = (x52 & x55)
    x57 = (~(x0))
    x58 = (~(x30))
    x59 = (x57 & x58)
    x60 = (x0 & x30)
    x61 = (x59 | x60)
    x62 = (x3 & x61)
    x63 = (x56 | x62)
    x64 = (x0 == x36)
    x65 = (x5 == x64)
    x66 = (x7 & x8)
    x67 = (~(x7))
    x68 = (~(x8))
    x69 = (x67 & x68)
    x70 = (x66 | x69)
    x71 = (x6 == x70)
    x72 = (x4 ^ x71)
    x73 = (x9 == x10)
    x74 = (x14 > x73)
    x75 = (x0 ^ x6)
    x76 = (~(x75))
    x77 = (x76 < x27)
    x78 = (x3 == x0)
    x79 = (x18 > x78)
    x80 = (x10 @ x42)
    x81 = (x80 == x79)
    x82 = (x5 ^ x0)
    x83 = (~(x82))
    x84 = (x83 < x49)
    x85 = (x84 ^ x79)
    x86 = (x1 == x81)
    x87 = (x86 ^ x14)
    x88 = (~(x87))
    x89 = (x88 == x74)
    x90 = (x89 ^ x5)
    x91 = (~(x90))
    x92 = (x65 @ x72)
    x93 = (x92 ^ x91)
    x94 = (~(x93))
    x95 = (x0 == x49)
    x96 = (x95 == x85)
    x97 = (x74 & x5)
    x98 = (~(x74))
    x99 = (~(x5))
    x100 = (x98 & x99)
    x101 = (x97 | x100)
    x102 = (x101 == x96)
    x103 = (x30 @ x7)
    x104 = (x103 == x102)
    x105 = (x36 & x20)
    x106 = (x9 ^ x105)
    x107 = (~(x106))
    x108 = (x107 == x77)
    x109 = (x108 == x27)
    x110 = (x81 == x109)
    x111 = (x85 ^ x63)
    x112 = (~(x111))
    x113 = (x51 == x112)
    x114 = (x113 ^ x77)
    x115 = (x63 @ x51)
    x116 = (x115 ^ x114)
    x117 = (~(x116))
    x118 = (x110 ^ x117)
    x119 = (x110 @ x94)
    x120 = (x117 == x119)
    x121 = (x104 == x94)
    x122 = (x120 > x121)
    x123 = (x122 ^ x104)
    x124 = (x110 @ x94)
    x125 = (x124 ^ x104)
    x126 = (~(x125))
    x127 = (x118 @ x126)
    x128 = (x127 ^ x117)
    x129 = (~(x128))
    x130 = (x104 == x94)
    x131 = (x94 > x130)
    x132 = (x110 @ x94)
    x133 = (x132 ^ x94)
    x134 = (~(x133))
    x135 = (x131 @ x117)
    x136 = (x104 == x135)
    x137 = (x136 ^ x134)
    x138 = (x117 ^ x110)
    x139 = (~(x138))
    x140 = (x139 < x104)
    x141 = (x140 @ x110)
    x142 = (x141 ^ x118)
    x143 = (~(x142))
    x144 = (x110 @ x94)
    x145 = (x144 == x143)
    x146 = (x137 ^ x145)
    x147 = (x129 ^ x145)
    x148 = (x7 == x11)
    x149 = (x148 < x137)
    x150 = (x129 ^ x123)
    x151 = (~(x150))
    x152 = (x151 < x18)
    x153 = (x36 ^ x0)
    x154 = (x5 == x153)
    x155 = (x145 > x154)
    x156 = (x129 == x123)
    x157 = (x156 < x8)
    x158 = (x10 ^ x9)
    x159 = (~(x158))
    x160 = (x159 < x147)
    x161 = (x137 == x123)
    x162 = (x9 > x161)
    x163 = (x123 ^ x129)
    x164 = (x163 == x146)
    x165 = (x42 > x164)
    x166 = (x129 ^ x146)
    x167 = (~(x166))
    x168 = (x167 == x123)
    x169 = (x168 & x10)
    x170 = (x137 @ x20)
    x171 = (x155 == x170)
    x172 = (x4 == x8)
    x173 = (x6 == x172)
    x174 = (x173 & x147)
    x175 = (x129 @ x7)
    x176 = (x175 == x174)
    x177 = (x145 @ x72)
    x178 = (x177 ^ x160)
    x179 = (~(x178))
    x180 = (x146 @ x49)
    x181 = (x180 == x162)
    x182 = (x123 & x51)
    x183 = (x137 @ x36)
    x184 = (x183 == x182)
    x185 = (x137 == x123)
    x186 = (x27 > x185)
    x187 = (x169 & x157)
    x188 = (~(x169))
    x189 = (~(x157))
    x190 = (x188 & x189)
    x191 = (x187 | x190)
    x192 = (x186 == x191)
    x193 = (x123 @ x63)
    x194 = (x193 == x176)
    x195 = (x8 & x6)
    x196 = (~(x8))
    x197 = (~(x6))
    x198 = (x196 & x197)
    x199 = (x195 | x198)
    x200 = (x4 == x199)
    x201 = (x200 @ x147)
    x202 = (x201 ^ x179)
    x203 = (~(x202))
    x204 = (x181 ^ x165)
    x205 = (x192 & x171)
    x206 = (~(x192))
    x207 = (~(x171))
    x208 = (x206 & x207)
    x209 = (x205 | x208)
    x210 = (x165 == x209)
    x211 = (~(x160))
    x212 = (~(x152))
    x213 = (x211 & x212)
    x214 = (x160 & x152)
    x215 = (x213 | x214)
    x216 = (x210 & x215)
    x217 = (x160 < x152)
    x218 = (x160 > x152)
    x219 = (x217 | x218)
    x220 = (~(x210))
    x221 = (x219 & x220)
    x222 = (x157 ^ x169)
    x223 = (x203 == x165)
    x224 = (x155 == x223)
    x225 = (x152 ^ x224)
    x226 = (x0 == x5)
    x227 = (x146 > x226)
    x228 = (x194 == x157)
    x229 = (x228 ^ x152)
    x230 = (~(x229))
    x231 = (x227 ^ x230)
    x232 = (x203 == x171)
    x233 = (x129 @ x7)
    x234 = (x233 == x179)
    x235 = (x123 @ x51)
    x236 = (x234 == x235)
    x237 = (x236 ^ x169)
    x238 = (~(x237))
    x239 = (x171 == x238)
    x240 = (x129 & x30)
    x241 = (x194 & x240)
    x242 = (~(x194))
    x243 = (~(x240))
    x244 = (x242 & x243)
    x245 = (x241 | x244)
    x246 = (x245 == x204)
    x247 = (x171 == x192)
    x248 = (x247 ^ x246)
    x249 = (x149 == x204)
    x250 = (x169 == x249)
    x251 = (x157 ^ x250)
    x252 = (x184 == x192)
    x253 = (x252 ^ x162)
    x254 = (~(x253))
    x255 = (x216 | x221)
    x256 = (x222 == x225)
    x257 = (x181 == x231)
    x258 = (x232 == x192)
    x259 = (x239 ^ x157)
    x260 = (~(x248))
    x261 = (x184 == x251)
    x262 = (x176 == x254)
    return bits([x255, x256, x257, x258, x259, x260, x261, x262])

def aes128_ecb_sbox_inv_opt(xs):
    (x0,x1,x2,x3,x4,x5,x6,x7) = xs
    x8 = (x1 == x3)
    x9 = (x0 == x1)
    x10 = (x3 ^ x4)
    x11 = (x4 == x7)
    x12 = (x0 ^ x3)
    x13 = (x1 == x12)
    x14 = (x6 == x8)
    x15 = (x7 == x14)
    x16 = (x7 == x10)
    x17 = (x9 ^ x11)
    x18 = (x9 ^ x6)
    x19 = (~(x18))
    x20 = (x7 == x19)
    x21 = (x7 == x6)
    x22 = (x21 == x10)
    x23 = (x2 == x15)
    x24 = (x6 == x1)
    x25 = (x24 == x11)
    x26 = (x2 == x5)
    x27 = (x5 == x6)
    x28 = (x2 == x4)
    x29 = (x8 ^ x26)
    x30 = (x6 & x28)
    x31 = (~(x6))
    x32 = (~(x28))
    x33 = (x31 & x32)
    x34 = (x30 | x33)
    x35 = (x1 == x34)
    x36 = (x4 & x27)
    x37 = (~(x4))
    x38 = (~(x27))
    x39 = (x37 & x38)
    x40 = (x36 | x39)
    x41 = (x3 == x40)
    x42 = (x17 ^ x41)
    x43 = (x13 ^ x4)
    x44 = (~(x43))
    x45 = (x44 < x41)
    x46 = (x41 ^ x17)
    x47 = (~(x46))
    x48 = (x47 < x10)
    x49 = (x45 ^ x48)
    x50 = (x41 ^ x17)
    x51 = (~(x50))
    x52 = (x51 < x10)
    x53 = (x9 @ x17)
    x54 = (x52 == x53)
    x55 = (x20 & x29)
    x56 = (~(x55))
    x57 = (x17 > x27)
    x58 = (x17 < x27)
    x59 = (x57 | x58)
    x60 = (x56 & x59)
    x61 = (~(x17))
    x62 = (~(x27))
    x63 = (x61 & x62)
    x64 = (x17 & x27)
    x65 = (x63 | x64)
    x66 = (x55 & x65)
    x67 = (x60 | x66)
    x68 = (x3 == x0)
    x69 = (x68 < x13)
    x70 = (x69 == x67)
    x71 = (x49 == x70)
    x72 = (x0 == x26)
    x73 = (x72 < x15)
    x74 = (x20 @ x29)
    x75 = (x74 ^ x73)
    x76 = (~(x75))
    x77 = (x54 ^ x76)
    x78 = (~(x77))
    x79 = (x78 == x11)
    x80 = (x22 & x35)
    x81 = (x35 == x80)
    x82 = (x81 ^ x22)
    x83 = (~(x82))
    x84 = (x8 & x16)
    x85 = (x83 & x49)
    x86 = (~(x83))
    x87 = (~(x49))
    x88 = (x86 & x87)
    x89 = (x85 | x88)
    x90 = (x84 == x89)
    x91 = (x25 @ x23)
    x92 = (x54 == x91)
    x93 = (x2 == x10)
    x94 = (x22 @ x35)
    x95 = (x94 ^ x92)
    x96 = (~(x95))
    x97 = (x96 ^ x93)
    x98 = (x22 @ x35)
    x99 = (x98 ^ x22)
    x100 = (~(x99))
    x101 = (x100 ^ x35)
    x102 = (x8 @ x16)
    x103 = (x102 ^ x101)
    x104 = (~(x103))
    x105 = (x49 & x104)
    x106 = (~(x49))
    x107 = (~(x104))
    x108 = (x106 & x107)
    x109 = (x105 | x108)
    x110 = (x97 == x109)
    x111 = (x90 & x71)
    x112 = (x71 ^ x79)
    x113 = (x97 == x111)
    x114 = (x112 > x113)
    x115 = (x79 ^ x114)
    x116 = (x112 @ x71)
    x117 = (x97 > x116)
    x118 = (x117 == x112)
    x119 = (x111 == x118)
    x120 = (x79 == x111)
    x121 = (x110 > x120)
    x122 = (x97 ^ x121)
    x123 = (x110 @ x79)
    x124 = (x90 > x123)
    x125 = (x124 & x111)
    x126 = (~(x124))
    x127 = (~(x111))
    x128 = (x126 & x127)
    x129 = (x125 | x128)
    x130 = (x129 == x110)
    x131 = (x79 @ x90)
    x132 = (x131 < x110)
    x133 = (x132 ^ x111)
    x134 = (~(x133))
    x135 = (x110 == x134)
    x136 = (x135 ^ x119)
    x137 = (x111 ^ x97)
    x138 = (~(x137))
    x139 = (x138 < x112)
    x140 = (x122 == x79)
    x141 = (x140 ^ x139)
    x142 = (~(x141))
    x143 = (x119 == x142)
    x144 = (x130 == x143)
    x145 = (x26 ^ x0)
    x146 = (~(x145))
    x147 = (x146 < x122)
    x148 = (x115 == x119)
    x149 = (x35 > x148)
    x150 = (x115 == x119)
    x151 = (x22 > x150)
    x152 = (x122 == x115)
    x153 = (x152 < x10)
    x154 = (x4 == x13)
    x155 = (x144 > x154)
    x156 = (x119 == x130)
    x157 = (x9 > x156)
    x158 = (x142 @ x42)
    x159 = (x158 == x153)
    x160 = (x136 @ x17)
    x161 = (x160 ^ x155)
    x162 = (~(x161))
    x163 = (x119 & x16)
    x164 = (x130 @ x13)
    x165 = (x163 == x164)
    x166 = (x130 ^ x122)
    x167 = (~(x166))
    x168 = (x167 < x29)
    x169 = (x115 @ x23)
    x170 = (x169 ^ x168)
    x171 = (~(x170))
    x172 = (x115 @ x25)
    x173 = (x172 == x149)
    x174 = (x119 @ x8)
    x175 = (x174 ^ x159)
    x176 = (~(x175))
    x177 = (x176 ^ x151)
    x178 = (x122 ^ x130)
    x179 = (x178 @ x20)
    x180 = (x157 == x179)
    x181 = (x3 == x0)
    x182 = (x181 < x130)
    x183 = (x122 @ x15)
    x184 = (x183 ^ x147)
    x185 = (~(x184))
    x186 = (x185 ^ x182)
    x187 = (x142 & x42)
    x188 = (x165 & x153)
    x189 = (~(x153))
    x190 = (~(x165))
    x191 = (x189 & x190)
    x192 = (x188 | x191)
    x193 = (x192 & x187)
    x194 = (~(x187))
    x195 = (x153 < x165)
    x196 = (x153 > x165)
    x197 = (x195 | x196)
    x198 = (x194 & x197)
    x199 = (x193 | x198)
    x200 = (x119 @ x16)
    x201 = (x200 == x177)
    x202 = (x144 @ x41)
    x203 = (x202 == x201)
    x204 = (x115 @ x23)
    x205 = (x204 == x149)
    x206 = (x177 & x162)
    x207 = (~(x177))
    x208 = (~(x162))
    x209 = (x207 & x208)
    x210 = (x206 | x209)
    x211 = (x136 @ x17)
    x212 = (x211 == x147)
    x213 = (x119 @ x8)
    x214 = (x213 ^ x212)
    x215 = (~(x214))
    x216 = (x0 == x3)
    x217 = (x130 > x216)
    x218 = (x173 == x215)
    x219 = (x218 ^ x217)
    x220 = (~(x219))
    x221 = (x199 ^ x220)
    x222 = (~(x221))
    x223 = (x186 ^ x199)
    x224 = (~(x223))
    x225 = (x151 == x224)
    x226 = (x225 & x162)
    x227 = (~(x225))
    x228 = (~(x162))
    x229 = (x227 & x228)
    x230 = (x226 | x229)
    x231 = (x130 == x122)
    x232 = (x231 < x29)
    x233 = (x177 == x147)
    x234 = (x233 == x232)
    x235 = (x157 & x171)
    x236 = (~(x157))
    x237 = (~(x171))
    x238 = (x236 & x237)
    x239 = (x235 | x238)
    x240 = (x239 == x186)
    x241 = (x171 == x177)
    x242 = (x241 ^ x165)
    x243 = (~(x242))
    x244 = (x149 ^ x203)
    x245 = (~(x244))
    x246 = (x122 @ x15)
    x247 = (x180 == x246)
    x248 = (x210 == x205)
    x249 = (x222 == x180)
    x250 = (x230 == x173)
    x251 = (x162 ^ x234)
    x252 = (x203 ^ x240)
    x253 = (x162 ^ x243)
    x254 = (x245 == x155)
    x255 = (x247 ^ x153)
    return bits([x248, x249, x250, x251, x252, x253, x254, x255])

def aes128_ecb_sbox_lookup_circuit(inputs, inverse = False):

    # Definition/implementation of function for which to
    # synthesize the circuit.
    def sbox_compute(offset = 99):
        (sbox, (p, q)) = ([offset] + [None]*255, (1, 1))

        def rotl(x, k):
            return ((x << k) | (x >> (8 - k)))%256

        for i in range(255):
            # Multiply p by 3.
            p = p ^ ((p << 1)%256) ^ (27 if 0 != (p & 128) else 0)

            # Divide q by 3 (equals multiplication by 246).
            a = q ^ (q << 1)%256
            b = a ^ (a << 2)%256
            c = b ^ (b << 4)%256
            q = c ^ (9 if (c & 128) != 0 else 0)

            # Compute the affine transformation.
            sbox[p] = (q^rotl(q, 1)^rotl(q, 2)^rotl(q, 3)^rotl(q, 4)) ^ offset

        return sbox

    def sbox_inv_compute():
        return [i for (_,i) in sorted([(o,i) for (i,o) in enumerate(sbox_compute())])]

    sbox_direction = sbox_compute if not inverse else sbox_inv_compute

    # Functions for synthesizing lookup table circuit.
    def vector_clauses(inputs):
        wire_cache = {}
        wire_cache[1] = {(0,):~inputs[0], (1,): inputs[0]}
        for width in range(2,len(inputs)+1):
            wire_cache[width] = {}
            (v, v_not) = (inputs[width-1], ~inputs[width-1])
            for k in wire_cache[width-1]:
                k_0 =  k + (0,)
                k_1 =  k + (1,)
                wire_cache[width][k_0] = v_not & wire_cache[width-1][k]
                wire_cache[width][k_1] = v     & wire_cache[width-1][k]
        return wire_cache[len(inputs)]

    def vector_clauses_concat(wire_cache_lft, wire_cache_rgt):
        wire_cache_cmb = {}
        for k_l in wire_cache_lft:
            for k_r in wire_cache_rgt:
                wire_cache_cmb[k_l + k_r] = wire_cache_lft[k_l] & wire_cache_rgt[k_r]
        return wire_cache_cmb

    def vector_clauses_or_all_per_position(clauses):
        d = [{} for i in range(8)]
        for k in range(0,8):
            for i in range(2**k,256,2**(1+k)):
                clause = clauses[i]
                if k >= 1:
                    clause |= reduce((lambda x,y: x|y), [d[j][(i+(2**j),i+((2**(j+1))-1))] for j in range(0,k)])
                d[k][(i,i+((2**k)-1))] = clause
        return list(reversed(d))

    clauses = vector_clauses_concat(
        vector_clauses_concat(vector_clauses(inputs[0:2]), vector_clauses(inputs[2:4])),
        vector_clauses_concat(vector_clauses(inputs[4:6]), vector_clauses(inputs[6:8]))
    )

    vectors_256 = list(product(*[[0,1]]*8))
    vectors_sbox = [tuple(bitlist(i,8)) for i in sbox_direction()]
    clauses_new = {}
    for (i,j) in zip(vectors_256, vectors_sbox):
        clauses_new[j] = clauses[i]
    clauses = clauses_new

    outs_per_bit_position = list(zip(*[list(bitlist(n,8)) for n in range(256)]))
    table_or_clauses = vector_clauses_or_all_per_position([clauses[v] for v in vectors_256])

    return bits([reduce((lambda x,y: x|y), table_or_clauses[i].values()) for i in range(0,8)])

def aes128_ecb_keys(key):
    # Convert the key into 4-byte portions.
    bss = list(parts(key, 4))

    def xor(xs, ys):
        return [x^y for (x,y) in zip(xs,ys)]

    # Use the optimized version of the S-box subcircuit.
    sbox_ = aes128_ecb_sbox_opt # aes128_ecb_sbox_lookup_circuit

    # Encryption/decryption round keys; first round.
    keys_for_rounds = [[v for v in bss]] 

    # Key expansion (fips-197 section 5.2).
    round_const = [1, 2, 4, 8, 16, 32, 64, 128, 16+11, 48+6]
    for t in range(0, 10):
        bss[0] = [
            bss[0][0]^sbox_(bss[3][1])^bits([constant(b) for b in bitlist(round_const[t], 8)]),
            bss[0][1]^sbox_(bss[3][2]),
            bss[0][2]^sbox_(bss[3][3]),
            bss[0][3]^sbox_(bss[3][0])
        ]
        bss[1] = xor(bss[1], bss[0]) # Have circuitry support bss[1] ^= bss[0] 
        bss[2] = xor(bss[2], bss[1]) # in the future.
        bss[3] = xor(bss[3], bss[2])
        keys_for_rounds.append([bs for bs in bss])

    return keys_for_rounds

def aes128_ecb_crypt(msg_and_key, inverse = False):
    (msg, key) = parts([bits.from_byte(byte, input) for byte in msg_and_key], 2)

    def xor(xs, ys):
        return [x^y for (x,y) in zip(xs,ys)]

    def xors_bytes(*xss):
        return xss[0] ^ xss[1] if len(xss) == 2 else xss[0] ^ xors_bytes(*xss[1:])

    # Use the optimized versions of the S-box subcircuits.
    # sbox_ = lambda inputs: aes128_ecb_sbox_lookup_circuit(inputs, inverse=inverse)
    sbox_ = aes128_ecb_sbox_opt if not inverse else aes128_ecb_sbox_inv_opt

    def xtime(x, n = 1): # Unused; simplified version below is used instead.
        return x if n==0 else xtime((x<<1)^mul8(((x>>7) & constants([0,0,0,0,0,0,0,1])), constants([0,0,0,1,1,0,1,1])), n-1)

    def xtime(x, n = 1):
        zero = constant(0)
        return x if n==0 else xtime((x<<1)^bits([zero,zero,zero,x[0],x[0],zero,x[0],x[0]]), n-1)

    def mul_gf28(x, y): # Unused; simplified version below is used instead.
        return xors_bytes(*[mul8(((y>>i) & constants([0,0,0,0,0,0,0,1])), xtime(x,i)) for i in range(5)])

    def mul_gf28(x, y):
        return xors_bytes(*[(bits([y[7-i]]*8) & xtime(x,i)) for i in range(5)])

    def mix(bss, add_keys_kr):
        return add_keys_kr([[ # Add keys last.
            bss[i][j] ^\
            (xtime(bss[i][j] ^ bss[i][(j+1)%4])) ^\
            (bss[i][0] ^ bss[i][1] ^ bss[i][2] ^ bss[i][3])
            for j in range(4)
        ] for i in range(4)])

    def mix_inv(bss, add_keys_kr):
        cs = [bits.from_byte(c, constant) for c in [0x0e, 0x09, 0x0d, 0x0b]]
        bss = add_keys_kr(bss) # Add keys first.
        return [[
            xors_bytes(*[mul_gf28(bs[j], cs[(i+4-j)%4]) for j in range(4)])
            for i in range(4)
        ] for bs in bss]

    # Mixing function for each direction.
    mix = mix if not inverse else mix_inv

    def add_keys(keys_for_round):
        return lambda bss: [[bss[i][j]^keys_for_round[i][j] for j in range(4)] for i in range(4)]

    # Permutations for each direction
    permute =\
        [[0,1,2,3],[1,2,3,0],[2,3,0,1],[3,0,1,2]] if not inverse else\
        [[0,3,2,1],[1,0,3,2],[2,1,0,3],[3,2,1,0]]

    # Compute keys for all rounds.
    keys_for_rounds = aes128_ecb_keys(key) if not inverse else list(reversed(aes128_ecb_keys(key)))

    # Convert to (ints ^ key).
    bss = [xor(p, k) for (p, k) in zip(parts(msg, 4), keys_for_rounds[0])]

    # Apply round transforms
    for r in range(1, 11):
        bss = [[sbox_(bss[i][j]) for j in range(4)] for i in range(4)] # Subtract bytes.
        bss = [[bss[p[j]][j] for j in range(4)] for p in permute] # Shift rows.
        bss = mix(bss, add_keys(keys_for_rounds[r])) if r < 10 else add_keys(keys_for_rounds[r])(bss)

    return bytes([int(outputs(bits_8)) for bits_8 in list(flats(bss))]).hex()

def synthesize_emit_test_aes128_direction(
        feedback, emit_file_and_check,
        path, function, sig, input_test, output_target
    ):
    name = path.split("/")[-1]
    print()
    bit.circuit(circuit())
    output_test = function(input_test)
    circ = bit.circuit()
    print("Synthesized `" + name + "` with " + str(len(circ.gate)) + " gates:")
    print(' * operation counts: ', {
        o.name(): circ.count(lambda g: g.operation == o) 
        for o in [op.not_, op.and_, op.xor_, op.or_, op.nand_, op.nif_, op.id_, op.xnor_, op.nimp_]
    })
    feedback(name, "direct evaluation during synthesis", output_test, output_target)
    input_test = [b for byte in input_test for b in bitlist(byte, 8)]
    feedback(\
        name, "data structure evaluated on input",
        bitlist(circ.evaluate(input_test)).hex(), output_target
    )
    circ.signature = sig
    emit_file_and_check(path, circ, input_test, output_target)
