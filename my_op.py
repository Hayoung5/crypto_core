"""
define operation of Bitcoin's smart contract language "Script"
operation has its opcode for identifying. OP_CODE_FUNCTIONS save the opcode as dictionary
"""

from helper import hash256, hash160
from ecc import S256Point, Signature



def encode_num(num):
    if num == 0:
        return b''
    abs_num = abs(num)
    negative = num < 0
    result = bytearray()
    while abs_num:
        result.append(abs_num & 0xff)
        abs_num >>= 8
    # if the top bit is set,
    # for negative numbers we ensure that the top bit is set
    # for positive numbers we ensure that the top bit is not set
    if result[-1] & 0x80:
        if negative:
            result.append(0x80)
        else:
            result.append(0)
    elif negative:
        result[-1] |= 0x80
    return bytes(result)


def decode_num(element):
    if element == b'':
        return 0
    # reverse for big endian
    big_endian = element[::-1]
    # top bit being 1 means it's negative
    if big_endian[0] & 0x80:
        negative = True
        result = big_endian[0] & 0x7f
    else:
        negative = False
        result = big_endian[0]
    for c in big_endian[1:]:
        result <<= 8
        result += c
    if negative:
        return -result
    else:
        return result

def op_dup(stack):
    if len(stack) < 1 :    # if there is no element on the stack, retrun False than the script will be invalid
        return False
    else:
        stack.append(stack[-1])
        return True

def op_hash256(stack):
    if len(stack) < 1 :    # if there is no element on the stack, retrun False
        return False
    else:
        X = stack.pop()    # use list.pop() instead of list[-1] to take last element and remove it from the list 
        stack.append(hash256(X))
        return True

def op_hash160(stack):
    if len(stack) < 1 :    # if there is no element on the stack, retrun False
        return False
    else:
        X = stack.pop() 
        stack.append(hash160(X))
        return True

def op_checksig(stack, z):
    if len(stack) < 2:              # check that there are at least 2 elements on the stack
        return False
    sec_pubkey = stack.pop()                 # the top element of the stack is the SEC pubkey
    der_sig = stack.pop()[:-1]               # the next element of the stack is the DER signature
                                             # Signature format is [<DER signature> <1 byte hash-type>]. Hashtype value is last byte of the sig. So remove last byte using [:-1]
    try:
        point = S256Point.parse(sec_pubkey)  # take off the last byte of the signature as that's the hash_type
        sig = Signature.parse(der_sig)       # parse the serialized pubkey and signature into objects
    except (ValueError, SyntaxError) as e:
        return False      
    if point.verify(z,sig):                  # verify the signature using S256Point.verify()
        stack.append(encode_num(1))          # push an encoded 1 or 0 depending on whether the signature verified
    else: 
        stack.append(encode_num(0))
    return True

def op_checkmultisig(stack, z):
    if len(stack) < 1:              # check that there is at leat 1 elements on the stack
        return False
    n = decode_num(stack.pop())     # pop parameter n; the last element of the stack
    if len(stack) < n + 1 :         # if remain stack is shorter than n+1, It cannot be seen that it contains n pubkeys.
        return False
    sec_pubkeys = []
    for _ in range(n):
        sec_pubkeys.append(stack.pop())     # put n pubkeys into sec_pubkeys list.
    m = decode_num(stack.pop())     # pop parameter m and repeat above lines
    if len(stack) < m + 1 :
        return False
    der_signatures = []
    for _ in range(m):
        der_signatures.append(stack.pop()[:-1])     # Signature format is [<DER signature> <1 byte hash-type>]. So remove last byte
    stack.pop()                    # this is dummy added to avoid Off-by-one bug
    try:
        points = [S256Point.parse(sec) for sec in sec_pubkeys]          # parse sec_pubkeys and listed
        sigs = [Signature.parse(der) for der in der_signatures]         # parse der_signautres and listed
        #if m keys among n keys verify m signature return 1
        for sig in sigs:
            if len(points) == 0:
                return False
            while points:
                point = points.pop(0)
                if point.verify(z, sig):
                    break
        stack.append(encode_num(1))
    except (ValueError, SyntaxError):
        return False
    return True
    

OP_CODE_FUNCTIONS = {
    118: op_dup,
    169: op_hash160,
    170: op_hash256,
    173: op_checksig,
}

OP_CODE_NAMES = {
    118: "op_dup",
    169: "op_hash160",
    170: "op_hash256",
    173: "op_checksig",
}
