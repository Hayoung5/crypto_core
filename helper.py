from unittest import TestSuite, TextTestRunner
import hashlib

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3

def run(test):
    suite = TestSuite()
    suite.addTest(test)
    TextTestRunner().run(suite)

def hash256(s):
    '''two rounds of sha256'''
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

#Since SEC form use long length (65 or 33 bytes) Base58 was recomended (now use Bech32)
def encode_base58(s):
    count = 0
    for c in s:                                 #count "0" bytes in given byte string
        if c == 0:
            count += 1
        else:
            break
    num = int.from_bytes(s, 'big')              #convert given byte string to integer
    prefix = '1' * count
    result = ''
    while num > 0:                              #convert given int using BASE58_ALPHABET
        num, mod = divmod(num, 58)              #divmod(a,b) return quotient(a//b) and mod(a%b)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result                      #prefix expresses the number of 0s as repetitions of "1", which is necessary in p2pkhd

def encode_base58_checksum(b):
    return encode_base58(b + hash256(b)[:4])

# get 20 bytes hash from BTC address encoded using Base58
def decode_base58(s):
    num = 0
    for c in s:                                     # convert address expressed using Base58 to number again
        num *= 58
        num += BASE58_ALPHABET.index(c)
    combined = num.to_bytes(25, byteorder='big') 
    checksum = combined[-4:]
    if hash256(combined[:-4])[:4] != checksum:      # If the address was properly generated, it should match.
        raise ValueError('bad address: {} {}'.format(checksum, hash256(combined[:-4])[:4]))
    return combined[1:-4]                           # takes the part excluding the 1st 1byte(prefit) and the last 4bytes(checksum)

def hash160(s):
    """sha256 folloew by ripemd160"""
    return hashlib.new( "ripemd160" , hashlib.sha256(s).digest()).digest()

def little_endian_to_int(b):
    return int.from_bytes(b,'little')

def int_to_little_endian(i,length):
    return i.to_bytes(length,'little')

#varint is "variable integer"
def read_varint(s):
    """read_variant reads a variable integer from a stream in varint form (and return to int)"""
    i = s.read(1)[0]
    if i == 0xfd :
        #0xfd means the next 2 bytes are the number: 253 ~ 2^16-1
        return little_endian_to_int(s.read(2))
    elif i == 0xfe : 
        #0xfe means the next 4 bytes are the number: 2^16 ~ 2^32-1
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        #0xff means the next 8 bytes are the number: 2^32 ~ 2^64 -1
        return little_endian_to_int(s.read(8))
    else:
        #anything else is just the integer: 0 ~ 252
        return i

def encode_varint(i):
    """encodes an integer as a variant (get int and return bytes in varint form)"""
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(i, 8)
    else:
        raise ValueError('integer too large: {}'.format(i))

