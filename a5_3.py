# A5/3 for GSM
# based on: https://www.gsma.com/aboutus/wp-content/uploads/2014/12/a53andgea3specifications.pdf

import math
from kasumi import Kasumi

# definiujemy potrzebne operacje na bitach
'''
def XOR(bits1, bits2):
    pass
    
def bin_to_hex():
    pass
    
def hex_to_bin():
    pass

'''


# KGcore
def kgcore(ca, cb, cc, cd, ce, ck, cl):

    # ca 8bit
    # cb 5bits
    # cc 32 bits
    # cd 1bit
    # ce 16bits
    # ck 128bits
    # cl number from 1 to 2^19 (in GSM it's 228)
    # co output cl bits

    # initalisation
    # sum to 64bits
    a = cc + cb + cd + "00" + ca + ce

    km = 0x55555555555555555555555555555555

    a = int(a, 2)

    a = KASUMI(a, (ck ^ km))

    # keystream generation

    # should be 4
    BLOCKS = math.ceil(cl/64)

    KSB = [0] * (BLOCKS + 1)
    KSB[0] = 0

    co = ""

    for n in range(BLOCKS):
        BLKCNT = n

        print(BLKCNT)
        print(a)
        KSB[n+1] = KASUMI(a ^ BLKCNT ^ KSB[n], ck)

        print(KSB)

        co = co + str(bin(KSB[n+1])[2:].zfill(64))
        print("co: ", co)

    print("Before truncating: ", len(co))
    # truncate
    co = co[:len(co) - 28]

    print("After truncating: ", len(co))
    print("co: ", co)

    return co


# test
def KASUMI(inp, key):
    # takes 64bits long input and 128bits long key
    kasumi = Kasumi()

    kasumi.set_key(key)

    return kasumi.enc(inp)


def a5_3_encryption(count, kc):
    # count 22 bits (frame dependent input)
    # kc is of size klen

    klen = 64

    ca = '00001111'
    cb = '00000'
    cc = '0000000000' + count
    cd = '0'
    ce = '0000000000000000'
    # ck = kc[0:klen]
    ck = kc
    cl = 228

    co = kgcore(ca, cb, cc, cd, ce, ck, cl)

    # uplink
    BLOCK1 = co[0:114]
    # downlink
    BLOCK2 = co[114:]
    # print(co)
    # print(type(co))
    # print(len(co))

    print("BLOCK1: ", BLOCK1)
    print("BLOCK2: ", BLOCK2)

# tests

# input: 22 bits long frame number and 128bits long key (in hex 32 digits)
a5_3_encryption('0101010101001010101010', 0x9900aabbccddeeff1122334455667788)

