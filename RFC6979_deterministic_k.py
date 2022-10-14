import hashlib
import hmac


# Example of deterministic key. rfc6979 
# EC = sect163k1, f(x) = x^163 + x^6 + x^3 + 1, y^2 + xy = x^3 + ax^2 + b while a=1, b=1

a=1; b=1
q = 0x4000000000000000000020108A2E0CC0D99F8A5EF
qlen = 163
Ux = 0x79AEE090DB05EC252D5CB4452F356BE198A4FF96F 
Uy = 0x782E29634DDC9A31EF40386E896BAA18B53AFA5A3


def printf(K):
    print(hex(int.from_bytes(K,'big')))

def deterministic_K(m, x):
    # Part a
    h1 = hashlib.sha256(bytes(m,'utf-8')).digest()               #digest() return bytes type value
    h1 = (int.from_bytes(h1,'big') >> (256-qlen))% q             #bits2octets by take 163 leftmost digit of bin then mod q
    h1 = h1.to_bytes(21,'big')                                   # 21 octets
    x = x.to_bytes(21,'big')  

    # Step b, c
    K = b'\x00' * 32
    v = b'\x01' * 32

    S256 = hashlib.sha256
    # Step d
    K = hmac.new(K, v + b'\x00' + x + h1, S256).digest()        #this gives 0x9999a9bfef972d3346911883fad7951d23f2c8b47f420222d1171eeeeac5ab8
    # Step e
    v = hmac.new(K, v, S256).digest()                           #this gives 0xd5f4030f755ee86aa10bba8c09df114ff6b6111c238500d13c7343a8c01becf7
    # Step f
    K = hmac.new(K, v + b'\x01' + x + h1, S256).digest()        #this gives 0xcf2fe96d5619c9ef53cb7417d49d37ea68a4ffed0d7e623e38689289911bd57
    # Step g
    v = hmac.new(K, v, S256).digest()                           #this gives 0x783457c1cf3148a8f2a9ae73ed472fa98ed9cd925d8e964ce0764def3f842b9a
    # Step h                                                   
    T = 0
    while True:
        v = hmac.new(K, v, S256).digest()
        T = int.from_bytes(v, 'big')
        tlen = 256                          # tlen = len(bin(T))-2. now I use fixed number of 256. since the hmac return 256 bit because of sha256
        # this part show k = bits2int(T)
        if qlen < tlen :
            T >>= (tlen - qlen)
        else:
            q2 = q >> (qlen - tlen)
            q2 <<= (qlen - tlen)
            T += q2
        k = T
        if k >= 1 and k < q:
            return k, h1
        else:
            K = hmac.new(K, v + b'\x00', S256).digest()
            v = hmac.new(K, v, S256).digest()
    

