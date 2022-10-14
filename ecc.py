#ecc for programing crypto currency


#class for field element of finite field
#finite set has prime number as an order of the set
#the order of the set is same as the size of the set
#F_p = {0, 1, ... p-1} 
from io import BytesIO
from bz2 import compress
from tkinter.messagebox import NO
import hashlib
import hmac
from helper import hash256, hash160, encode_base58_checksum

class FieldElement:

    def __init__(self, num, prime) :
        if num >= prime or num < 0:
            error = 'Num {} not in field range 0 to {}'.format(num, prime - 1)
            raise ValueError(error)
        self.num = num
        self.prime = prime
    
    #repersent field element
    def __repr__(self):
        return 'FieldElement_{}({})'.format(self.prime, self.num)

    #return bool as a result of condition a==b, a!=b
    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime 

    def __ne__(self, other):
        return not (self == other)

    #define addition and subtraction of the finite field
    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two element in different Fields')
        num = (self.num + other.num) % self.prime
        return self.__class__(num, self.prime)

    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot subtract two element in different Fields')
        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime)

    #define multiplication and exponent of the finite field
    def __mul__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot multiply two element in different Fields')
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)

    def __pow__(self, exponent):
        n = exponent % (self.prime -1) #this allow negative exponent and fast calc using Fermat's Little Theorem 1 = a^(p-1))
        num = pow(self.num, n, self.prime) #calc num**n%prime
        return self.__class__(num, self.prime)

    #define division of the finite field
    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot divide two element in different Fields')
        #return a/b =a*b^(p-2)
        return self * pow(other,(self.prime-2))

    #degfine scalar multiplication. __rmul__ is right multiplicity. it define multiplicity about right obeject
    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        return self.__class__(num=num, prime=self.prime)

# class for elliptic curve

class Point:
 
    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        #consider point at infinite using None
        if self.x is None and self.y is None :
            return
        if self.y**2 != self.x**3 + a*x + b:
            raise ValueError('({}, {}) is not on the elliptic curve'.format(x,y))
    
    #repersent Point on the elliptic curve
    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        elif isinstance(self.x, FieldElement):              #isinstance(a,type) return bool whether the type of a and the type is the same.
            return 'Point({},{})_{}_{} FieldElement({})'.format(
                self.x.num, self.y.num, self.a.num, self.b.num, self.x.prime)
        else:
            return 'Point({},{})_{}_{}'.format(self.x, self.y, self.a, self.b)

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y \
            and self.a == other.a and self.b == other.b

    def __ne__(self, other):
        return not (self == other)

    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise ValueError('Point {}, {} are not on the same curve'.format(self,other))
        
        #addtion of identity : A + I = A
        if self.x is None: 
            return other
        if other.x is None: 
            return self

        #addition with inverse : A + (-A) = I
        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)
        
        #point doubling : P1 = P2
        if self == other:
            #exception when two points overlap and are parallel to the y-axis,
            #using y=0*x for considering expanding to finite field
            if self.y == 0 * self.x:       
                return self.__class__(None, None, self.a, self.b)
            else:
                s = (3 * self.x**2 + self.a) / (2 * self.y)  #slope of the tagent line
                x_3 = s**2 -2 * self.x            #x3 = s^2 - x1 -x2
                y_3 = s*(self.x - x_3) - self.y   #y3 = s(x1 - x3) - y1
                return self.__class__(x_3, y_3, self.a, self.b)

        #addition of two differnt points : P1!=P2
        if self.x != other.x:
            diff_y = other.y - self.y
            diff_x = other.x - self.x
            s = diff_y/diff_x            #slope of the expanding line of the P1, P2
            x_3 = s**2 - self.x - other.x       #x3 = s^2 - x1 - x2
            y_3 = s*(self.x - x_3) - self.y     #y3 = s(x1 - x3) - y1
            return self.__class__(x_3, y_3, self.a, self.b)
    
    #define scalar multiplication using __rmul__
    # def __rmul__(self, coefficient):
    #     product = self.__class__(None, None, self.a, self.b)
    #     for _ in range(coefficient):
    #         product += self
    #     return product

    #above definition take too much time for calcultaion with large coefficient
    #using binary expansion take result using lesser loop (=log_2 (N), when N is the number of repetitions of multiplication.)
    #it might called "Double-and-add" algorithm...
    def __rmul__(self, coefficient):
        coef = coefficient
        G = self                                                #generator point
        product = self.__class__(None, None, self.a, self.b)    #if coefficient is 0. return infinity point
        while coef != 0:                                        #this can be shortened to "while coef:"
            if coef & 1 :                                       #if AND operate between coef and 0b1 is not 0, then product += G
                product += G
                if coef == 1 : break                            #if coef==1, the loop ends without calculating the following calc
            G += G
            coef >>= 1                                          #A>>=B : shift bit of "A" to right by "B" and reassign to "A". this remove right bit of binary coef
                                                                #thus loop run (digits of binart coef - 1) times. and it sames as log_2(coef)
        return product
    

#parameters of secp256k1 : y**2 = x**3 + 7 (y**2 = x**3 + ax + b)
A = 0
B = 7
P = 2**256 - 2**32 - 977                                                        #prime number
Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798         #x of generator point
Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8         #y of generator point
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141          #order of the group, N*G=0


#specialized class for secp256k1
#reference of concept of super class : https://rednooby.tistory.com/56

#S256Field define finite field with prime number P = 2**256 - 2**32 - 977       
class S256Field(FieldElement):

    def __init__(self, num, prime=None):
        super().__init__(num, prime=P)                     #Inherit num, prime from FieldElement

    def __repr__(self):
        return '{:x}'.format(self.num).zfill(64)           #{:x}.format(num) changes num to hexadecimal number. zfill(64) add leading zeros to make 64 digits

    def sqrt(self):
        return self**((P + 1) // 4)                        #this function use the features that P of secp256k1 satisfy P%4=3, (P+1)%4 = 0.


#S256Point difine point(x,y) on the elliptic curve secp256k1. x, y, a, b are field elements of S256 fields. 
class S256Point(Point):
    
    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(A), S256Field(B)
        if type(x) == int:
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)                #if x is infinity point(x=None), do not use S256Field(x), just pass x as it is

    def __rmul__(self, coefficient):
        coef = coefficient % N                                  #since nG=0, using coefficient % N reduce calculation process.
        return super().__rmul__(coef)

    def verify(self, z, sig):                                   #varify given signature whether is true.
        s_inv = pow(sig.s, N-2, N)                              #pow(a,b,c) is difined as (a^b)%c, N is order of the group and also prime number.
        u = z * s_inv % N                                       #u = z/s
        v = sig.r * s_inv % N                                   #v = r/x
        R = u * G + v * self                                    #uG + vP = R
        return R.x.num == sig.r                                 #uG+vP = R, So do x value of R and r match?
    
    #sec is Standards for Efficient Crytography, used for serialization of public key
    def sec(self, compressed=True):
        """returns the binary version of the SEC format"""

        if compressed:                                                     #compressed case use only 33 bytes for sapce saving               
            if self.y.num % 2 == 0:                                 
                return b'\x02' + self.x.num.to_bytes(32, 'big')            #if y is even use \x02
            else: return b'\x03' + self.x.num.to_bytes(32, 'big')          #if y is odd use \x03
        else:
            return b'\x04' + self.x.num.to_bytes(32, 'big') + self.y.num.to_bytes(32, 'big')
    
    #parse return public key point from SEC. In compressed case, recalc y from x
    @classmethod                                            #https://wikidocs.net/16074
    def parse(cls, sec_bin):
        """returns a Point object from a SEC binary (not hex)"""
        if sec_bin[0] == 4 :                #not compressed case
            x = int.from_bytes(sec_bin[1:33], 'big')
            y = int.from_bytes(sec_bin[33:65], 'big')
            return S256Point(x=x, y=y)

        is_even = sec_bin[0] == 2          #compressed case with even y

        x = S256Field(int.from_bytes(sec_bin[1:], 'big'))
        #y is calc from secp256k1. y = +-sqrt(x^3 + 7) = v or P-v. 
        #since P is odd, y values are even and odd, respectively.

        w2 = x**3 + S256Field(B)
        v = w2.sqrt()

        if v.num % 2 == 0:
            even_v = v
            odd_v = S256Field(P - v.num)
        else:
            even_v = S256Field(P - v.num)
            odd_v = v

        if is_even:
            return S256Point(x, even_v)
        else:
            return S256Point(x, odd_v)


    def hash160(self, compressed=True):
        return hash160(self.sec(compressed))

    #generate address of bitcoin from Public key using Base58 and above hash160 function (it use SEC as input of hash160 hashfunc)
    def address(self, compressed=True, testnet=False):
        """return the address strring"""
        h160 = self.hash160(compressed)
        if testnet :
            prefix = b'\x6f'
        else:
            prefix = b'\x00'
        return encode_base58_checksum(prefix + h160)


G = S256Point(Gx,Gy)                                            #generator point


#express public key(public point) using class "Signature"
class Signature:
    
    def __init__(self, r, s):
        self.r = r
        self.s = s
    
    def __repr__(self):
        return 'Signature({:x},{:x})'.format(self.r, self.s)
    
    #der is Distinguished Encoding Rules, used for serialization of signature
    def der(self):                                              #Now the bitcoin use "Schnorr Signature" instead of DER
        rbin = self.r.to_bytes(32, byteorder='big')
        # rbin.lstrip(b'\x00') remove all null bytes(b'\x00') at the beginning from rbin
        rbin = rbin.lstrip(b'\x00')
        # if rbin has a high bit, add a \x00
        if rbin[0] & 0x80:
            rbin = b'\x00' + rbin
        result = bytes([2, len(rbin)]) + rbin  # <1>
        sbin = self.s.to_bytes(32, byteorder='big')
        # remove all null bytes at the beginning
        sbin = sbin.lstrip(b'\x00')
        # if sbin has a high bit, add a \x00
        if sbin[0] & 0x80:
            sbin = b'\x00' + sbin
        result += bytes([2, len(sbin)]) + sbin
        return bytes([0x30, len(result)]) + result

    @classmethod
    def parse(cls, signature_bin):
        s = BytesIO(signature_bin)
        compound = s.read(1)[0]
        if compound != 0x30:
            raise SyntaxError("Bad Signature")
        length = s.read(1)[0]
        if length + 2 != len(signature_bin):
            raise SyntaxError("Bad Signature Length")
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        rlength = s.read(1)[0]
        r = int.from_bytes(s.read(rlength), 'big')
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        slength = s.read(1)[0]
        s = int.from_bytes(s.read(slength), 'big')
        if len(signature_bin) != 6 + rlength + slength:
            raise SyntaxError("Signature too long")
        return cls(r, s)

from random import randint
#https://evan-moon.github.io/2019/07/14/what-is-random/

class PrivateKey:

    def __init__(self, secret):
        self.secret = secret            #secrete key, "e"
        self.point = secret * G         #public key, "P", P = e*G
    
    def hex(self):
        return'{:x}'.format(self.secret).zfill(64)              #zfill(64) add leading zeros to make 64 digits

    # #!! do not use below function to generate signature
    # def sign(self, z):                                          #exercise use random integer from python built-in module
    #     k = randint(0, N)                                       #random number between 0 and N. python random number is generated by Mersenne Twister
    #     r = (k * G).x.num                                       #x value of R (=kG) is one of the elements of the signature
    #     k_inv = pow(k, N-2, N)
    #     s = (z+ r*self.secret) * k_inv % N                      #s = (z + re)/k
    #     if s > N/2:                                             #bitcoin use low s due to transaction Malleability problem
    #         s = N - s                                           #since valid signature (r,s) is a point on the elliptic curve. (r,s) = (r,N-s) ref. 118p
    #     return Signature(r, s)

    """
    every signature must have differnt k, if not the secret key can be found.
    there is standard to generate unique "k" for every e and z. the standard called "RFC6979" (https://tools.ietf.org/html/rfc6979)
    the deterministic_k() part is it.
    """
    def sign(self, z):                                          #generate signatre (r, s)
        k = self.deterministic_k(z)
        r = (k * G).x.num
        k_inv = pow(k, N-2, N)
        s = (z+ r*self.secret) * k_inv % N                      #s = (z + re)/k
        if s > N/2:                                             #bitcoin use low s due to transaction Malleability problem
            s = N - s                                           #since valid signature (r,s) is a point on the elliptic curve. (r,s) = (r,N-s) ref. 118p
        return Signature(r, s)

    def deterministic_k(self, z):
        k = b'\x00' * 32
        v = b'\x01' * 32
        if z > N :
            z -= N
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32,'big')
        s256 = hashlib.sha256
        k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, 'big')
            if candidate >= 1 and candidate < N:
                return candidate  # <2>
            k = hmac.new(k, v + b'\x00', s256).digest()
            v = hmac.new(k, v, s256).digest()        

    #wif is Wallet Import Format. it convert secret key using hash256 and Base58
    def wif(self, compressed=True, testnet=False):
        secret_bytes = self.secret.to_bytes(32, "big")
        if testnet :
            prefix = b'\xef'
        else :
            prefix = b'\x80'
        if compressed:
            suffix = b'\x01'
        else :
            suffix = b''
        return encode_base58_checksum(prefix+ secret_bytes + suffix)
