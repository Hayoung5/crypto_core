#useful diagrams for describing sha 256 : https://www.cs.rit.edu/~ark/lectures/onewayhash/onewayhash.shtml



#useful constant B32
M = 1 << 32
B32 = M - 1                                              #B32 = 2*32, Used to limit bits to 32 bits: num & B32 same as num % 2**32

#preprocessing message to 512*n-bits
def preprocess(Message):
    if type(Message) != str :
            error = 'input is not string type'
            raise ValueError(error)

    if len(Message)*8 >= 2**64:                         #in that case, bin_len must be adjusted, use low 64-bit
        error = 'Message is too ling'

    #change message to binary number using ord(). 
    bin_m = ''
    length = 8 * len(Message)                           #length of message in 8-bit
    for i in Message:

        askii = ord(i)                                  #ord() : change str to ASKII code, chr() : change ASKII code to str
        bin_m += "{0:b}".format(askii).zfill(8)         #"{0:b}".format(x).zfill(8) change x to 8-bit

    bin_m += '1'                                        #add bit 1 to end of the message
    n0 = 512 - (length + 65) % 512                      #number of zeros to pad a with 512*n-bit (64 digits for describe length of message, 1 for describe end of the message)
    zeros = ''.zfill(n0)
    bin_m += zeros                                      #add "0" n0 times to right side
    bin_len = "{0:b}".format(length).zfill(64)          #length of message in 64-bit
    bin_m += bin_len
    return(bin_m)                                       #the type of result is integer
    #the bin_m must divide to chunks with 512-bit.  

bin_message = preprocess("python hash 256 wow")
print(len(bin_message))

'''
initial value H and K.
H is inital value of output(digest) and consisting of 8 32-bit number -> total 256-bit
K used for calculation, and consisting of 64 32-bit number
the code is written in big endian
'''

from telnetlib import WILL
from primePy import primes
first_8_primes = primes.first(8)
first_64_primes = primes.first(64)

H = []
for p in first_8_primes:
    sqrt = pow(p,0.5)                               #calc square root of p
    frac = sqrt - int(sqrt)                         #remove integer part to get fractional part
    frac = frac * (2 ** 32)                         #shift 32 digits
    H.append(int(frac))
    # h = hex(int(frac))                              #change integer part of frac in hex
    # H.append(h)

K = []
for p in first_64_primes:
    crt = pow(p,1/3)                               #calc cube root of p
    frac = crt - int(crt)                          #remove integer part to get fractional part
    frac = frac * (2 ** 32)                        #shift 32 digits
    K.append(int(frac))
    # k = hex(int(frac))                             #change integer part of frac in hex
    # K.append(k)

#Initialize working variables (chain variavles) to current hash value:
a = H[0]
b = H[1]
c = H[2]
d = H[3]
e = H[4]
f = H[5]
g = H[6]
h = H[7]

import numpy as np
from bitwise_operate import rho0, rho1, Sigma0, Sigma1, Choose, Majority

'''
make W[0...63] from message
Divde a chunk(512-bit) into 16 32-bit values to make W[0...15]
W[16...63] are the results of the MEXP(Message Expansion Function) operation
'''

def make_W_array():

    W = np.zeros(64, dtype=int)                                         #generate np.array with integer 0.
    
    for i in range(16):
        W[i] = int(str(bin_message)[32*i : 32*(i+1)], 2)                #do not forget add ",2" to change binary to decimal

    for i in range(16, 64):                                             #16 < i < 64
        W_raw = rho1(W[i-2]) + W[i-7] + rho0(W[i-15]) +  W[i-16]        #type of W[i] is integer.
        W[i] = W_raw & B32                                              #the element must be 32 bit
    return W

W = make_W_array()

'''
Apply round function to 8 chain vars for each loop, the chain vars are updated for every loops.
when T1 = h0 + Sigma1(e0) + Choose(e0, f0, g0) + K[i] + W[i], the updated vars are as following:
new a = T1 + Sigma0(a0) + Majority(a0, b0, c0)
new b = a
new c = b
new d = c
new e = d + T1
new f = e
new h = g
after all loops, the results are added to the initial value of chain vars and converted to bytes or hexadecimal number
'''

def FF(a0, b0, c0, d0, e0, f0, g0, h0, i):                              #define round function in sha256

    T1 = h0 + Sigma1(e0) + Choose(e0, f0, g0) + K[i] + W[i]
    d0 += T1
    h0 = T1 + Sigma0(a0) + Majority(a0, b0, c0)
    d0 = d0 & B32
    h0 = h0 & B32
    return h0, a0, b0, c0, d0, e0, f0, g0

def Main(a0, b0, c0, d0, e0, f0, g0, h0):
    
    for j in range(0, 64):
        a0, b0, c0, d0, e0, f0, g0, h0 = FF(a0, b0, c0, d0, e0, f0, g0, h0, j)

    chain_var64 = [a0, b0, c0, d0, e0, f0, g0, h0]                      #chain variable after 64 loop of round function
    DG = [(X + Y) & B32 for X,Y in zip(H, chain_var64)]                 #add initial value of chain var to the result and save as digest list, digest = hash value
    return b''.join(int(Di).to_bytes(4, 'big') for Di in DG)            #convert the elements of digest list to byte and combine to one line

BD = Main(a, b, c, d, e, f, g, h)                                       #BD is digest in bytes
print(BD)
print(''.join('{:02x}'.format(i) for i in BD))                          #'{:02x}'.format(i): convert each byte to a hex number with at list 2 digits. ''.join() combine the number in one line