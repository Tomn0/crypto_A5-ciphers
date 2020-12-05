# A5/3 for GSM
# based on: https://www.gsma.com/aboutus/wp-content/uploads/2014/12/a53andgea3specifications.pdf

import math
from kasumi import Kasumi


def XOR(bits1, bits2):
    """perform a XOR operation and return the output"""
    # ciągi muszą być równej długości
    xor_result = ""
    for index in range(len(bits1)):
        if bits1[index] == bits2[index]:
            xor_result += '0'
        else:
            xor_result += '1'
    return xor_result


def hexTobinary(hexdigits):
    binarydigits = ""
    for hexdigit in hexdigits:
        binarydigits += bin(int(hexdigit, 16))[2:].zfill(4)
    return binarydigits


def binary_to_decimal(binarybits):
    """ Convert binary bits to decimal"""
    decimal = int(binarybits, 2)
    return decimal


def decimal_to_binary(decimal):
    """ Convert decimal to binary bits"""
    binary4bits = bin(decimal)[2:].zfill(4)
    return binary4bits


# KGcore
# cc, ck, ca='00001111', cb='0000',  cd='0', ce='000000000000000',  cl=228


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
    a = cc + cb + cd + "00" + ca + ce

    # convert a to hex

    km = 0x55555555555555555555555555555555
    # km = hexTobinary('55555555555555555555555555555555')

    a = int(a, 2)

    a = KASUMI(a, (ck ^ km))

    # keystream generation

    # should be 4
    BLOCKS = math.ceil(cl/64)
    KSB = [0] * (BLOCKS + 1)
    KSB[0] = 0

    # co = [None] * BLOCKS
    co = ""

    for n in range(BLOCKS):

        BLKCNT = n

        KSB[n+1] = KASUMI(a ^ BLKCNT ^ KSB[n], ck)

        co = co + str(bin(KSB[n+1])[2:].zfill(64))

    print(co)

    return co


# test
def KASUMI(inp, key):
    # inp 64bits
    # translate into hexadecimal

    # hex_inp = hex(int(inp, 2)).zfill(16)
    # hex_key = hex(int(key, 2)).zfill(32)

    # hex_inp = "{0:#0{1}x}".format(int(inp, 2), 16)
    # hex_key = "{0:#0{1}x}".format(int(key, 2), 32)
    # źródło: https://stackoverflow.com/questions/12638408/decorating-hex-function-to-pad-zeros

    # hex_inp = int(inp, 2)
    # hex_key = int(key, 2)

    # print(hex(hex_inp))
    # print(hex(hex_key))

    kasumi = Kasumi()
    # print(hex(key))
    kasumi.set_key(key)

    return kasumi.enc(inp)


def a5_3_encryption(count, kc):
    # count 22 bits (frame dependent input)
    # kc is of size klen

    klen = 64

    ca = '00001111'
    cb = '0000'
    cc = '000000000' + count
    cd = '0'
    ce = '000000000000000'
    # ck = kc[0:klen]
    ck = kc
    cl = 228

    co = kgcore(ca, cb, cc, cd, ce, ck, cl)

    # uplink
    BLOCK1 = co[0:128]
    # downlink
    BLOCK2 = co[128:]
    # print(co)
    # print(type(co))
    # print(len(co))

    print("BLOCK1: ", BLOCK1)
    print("BLOCK2: ", BLOCK2)

# tests


a5_3_encryption('0101010101001010101010', 0x9900aabbccddeeff1122334455667788)
