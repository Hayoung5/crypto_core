#pseudo code of HMAC following : https://ko.wikipedia.org/wiki/HMAC
'''
        key:        Bytes    // Array of bytes
        message:    Bytes    // Array of bytes to be hashed
        hash:       Function // The hash function to use (e.g. SHA-1)
        blockSize:  Integer  // The block size of the hash function (e.g. 64 bytes for SHA-1)
        outputSize: Integer  // The output size of the hash function (e.g. 20 bytes for SHA-1)
'''

def my_hmac(key, message, hash, blockSize):

    # Keys longer than blockSize are shortened by hashing them
    if len(key) > blockSize :
        key = hash(key) # key is outputSize bytes long

    # Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
    if len(key) < blockSize :
        key = key.ljust(blockSize, b'\0') # Pad key with zeros to make it blockSize bytes long
        
    key = int.from_bytes(key, 'big')

    ipad = int.from_bytes(bytes([0x36] * blockSize),'big')    # repeated 0x36, do not forget [] and bytes()
    opad = int.from_bytes(bytes([0x5c] * blockSize),'big')

    i_key_pad = (key ^ ipad).to_bytes(blockSize,'big')  # Inner padded key
    o_key_pad = (key ^ opad).to_bytes(blockSize,'big')   # Outer padded key, 

    return hash(o_key_pad + hash(i_key_pad + message))

#Test with sha 256
from hashlib import sha256

def SHA256(s):
    return sha256(s).digest()

k = b'key'
m = b'The quick brown fox jumps over the lazy dog'
result = my_hmac(key = k, message = m, hash = SHA256, blockSize = sha256().block_size)
print(result)
print(''.join('{:02x}'.format(i) for i in result))

'''
HMAC_SHA256("key", "The quick brown fox jumps over the lazy dog") = 
f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
b'\xf7\xbc\x83\xf40S\x84$\xb12\x98\xe6\xaao\xb1C\xefMY\xa1IF\x17Y\x97G\x9d\xbc-\x1a<\xd8'
'''

#answer using hmac python module
import hmac
s256 = sha256
print( hmac.new(k,m,s256).digest())