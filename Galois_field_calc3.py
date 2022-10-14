# can compare table and calculator on http://www.ee.unb.ca/cgi-bin/tervo/calc2.pl?p=7
# Finite field arithmetic: addition, subtraction, multiplication, inverse https://en.wikipedia.org/wiki/Finite_field_arithmetic#Addition_and_subtraction
# inverse using extended Eclidean algorithm ref https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm

# class for element of binary field (2^m),so called Galois field, all elements in the GF(2^m) in in range [1, 2^m-1]
# p is modulo (polynomial wich has largest degree of m)

import math
import numpy as np

class FieldElement:

    def __init__(self, num, m, p) :
        if len(bin(num)) -2 >= m+1 or num < 0:
            error = 'Num {} not in field range 0 to 2^{}'.format(num, m)
            raise ValueError(error)
        self.num = num
        self.m = m
        self.p = p
    
    #repersent field element
    def __repr__(self):
        return 'FieldElement_2^{}({})'.format(self.m, self.num)

    #return bool as a result of condition a==b, a!=b
    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.m == other.m and self.p == other.p

    def __ne__(self, other):
        return not (self == other)

    #define addition and subtraction of the finite field
    def __add__(self, other):
        if self.m != other.m or self.p != other.p :
            raise TypeError('Cannot add two element in different Fields')
        num = (self.num ^ other.num)
        return self.__class__(num, self.m, self.p)

    def __sub__(self, other):
        if self.m != other.m or self.p != other.p :
            raise TypeError('Cannot subtract two element in different Fields')
        num = (self.num ^ other.num)
        return self.__class__(num, self.m, self.p)

    def __mod__(self, other):
        if self.m != other.m or self.p != other.p :
            raise TypeError('Cannot modulo two element in different Fields')
        num = (self.num % other.num)
        return self.__class__(num, self.m, self.p)

    #define multiplication and exponent of the finite field
    def __mul__(self, other):
        if self.m != other.m or self.p != other.p :
            raise TypeError('Cannot multiply two element in different Fields')

        # gf_multiply() in Galois_field_calc2.py
        if self.num > other.num :
            a,b = (self.num, other.num)
        else : a,b = (other.num, self.num)
        binary_b = bin(b)[2:]
        blen = len(binary_b)
        result = 0
        for i, bit in enumerate(binary_b):
            n = blen -i -1
            if bit == '1':
                shifted_a = a << n
                result ^= shifted_a

        # gf_divide() in Galois_field_calc2.py but removed q calc part
        while 1:
            n = len(bin(result))-len(bin(self.p)) 
            if n < 0 : break
            shifted_p = self.p << n
            result ^= shifted_p
            if result == 0 : break
        return self.__class__(result, self.m, self.p)

    def __pow__(self, exponent):
        if type(exponent) == "float" :
            raise TypeError('float exponent')
        n = exponent % (2**self.m -1)                       #this allow negative exponent and fast calc using Fermat's Little Theorem, FLT in bynary field 1 = a^(2^m-1))
        result = self.__class__(1, self.m, self.p)
        x = self                      
        if n == 0 :                                         #Using square-and-multiply algorithm (https://en.wikipedia.org/wiki/Exponentiation_by_squaring)
            return result
        else :
            while n > 1:
                if n & 1 :                                      # if odd
                    result *= x
                    x *= x
                else :
                    x *= x
                n >>= 1
            return x*result


    #define division of the finite field
    def __truediv__(self, other):
        if self.m != other.m or self.p != other.p :
            raise TypeError('Cannot divide two element in different Fields')
        if other.num == 0 :
            print("Divded by zero!")
            return self.__class__(None, self.m, self.p)
        else :
            #return a/b =a*b^(p-2)
            return self * pow(other,(2**self.m-2))

    # Not verified! the scalar product in binary fields doesn't seem to be defined. (2a = a+a = a-a = 0). Multiplication with odd numbers seems return the element itself.
    def __rmul__(self, coefficient):
        if coefficient%2  == 0 : 
            return self.__class__(0, self.m, self.p)
        else : return self

"""
Point on the EC called sect : y^2 + xy = x^3 + ax^2 + b. different from secp
The sect curves are curves over a binary field 𝔽2𝑚,  While the secp curves are over fields over a prime field - or 𝔽𝑝
standard recommendation of parameter : https://perso.univ-rennes1.fr/sylvain.duquesne/master/standards/sec2_final.pdf
EC = sect163k1, f(x) = x^163 + x^7 + x^6 + x^3 + 1, y^2 + xy = x^3 + ax^2 + b (Weierstrass equation) while a=1, b=1
Point multiplication on EC over binary field : https://downloads.hindawi.com/journals/scn/2020/4087873.pdf, https://hal.archives-ouvertes.fr/hal-01206530/document
"""
#Parameters for sect163k1 on F(2^163) with irreducible polynomial f(x) = x^163 + x^7 + x^6 + x^3 + 1

p163 = 0x800000000000000000000000000000000000000c9
m163 = 163                                          #the degree of the finite field GF(2m)
a163=1; b163=1                                      # this will be given as field element of GF(2m) 

q = 0x4000000000000000000020108A2E0CC0D99F8A5EF     # number of element of the field. same as N
qlen = 163
# #Normal Basis
# Ux = 0x5679b353caa46825fea2d3713ba450da0c2a4541
# Uy = 0x235b7c6710050689906bac3d9dec76a835591edb2

Ux = 0x79AEE090DB05EC252D5CB4452F356BE198A4FF96F
Uy = 0x782E29634DDC9A31EF40386E896BAA18B53AFA5A3
s = [2579386439110731650419537 , -755360064476226375461594]
V = -484546663253941077680431


class Point_for_sect:
 
    def __init__(self, x, y, a, b):
        #y^2 + xy = x^3 + ax^2 + b 
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        #consider point at infinite using None
        if self.x is None and self.y is None :
            return
        if self.y**2 + self.x * self.y != self.x**3 + a*x**2 + b:
           raise ValueError('({}, {}) is not on the elliptic curve'.format(x,y))
    
    #repersent Point on the elliptic curve
    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        elif isinstance(self.x, FieldElement):              #isinstance(a,type) return bool whether the type of a and the type is the same.
            return 'Point({},{})_{}_{} GF(2^{})'.format(
                self.x.num, self.y.num, self.a.num, self.b.num, self.x.m)
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
        
        #point doubling : P1 = +- P2                                                #since + is same as - in binary field, P1 = -P case is also doubling.
        if  self.x == other.x :
            if self.y == 0 * self.x or  other.y == 0 * other.x:     
                return self.__class__(None, None, self.a, self.b)
            else:
                s = (self.y)/(self.x) + self.x                                     #slope of the tagent line dy/dx (assign as "s")
                x_square = self.x**2                                                 #for decreasing time for calc
                x_3 = x_square + self.b/(x_square)                                  #x3 = s**2 + s + a = x1**2 + b/(x1**2)
                y_3= x_square + s*x_3 + x_3                                          #y3 = s(x1 + x3) + x3 + y1
                return self.__class__(x_3, y_3, self.a, self.b)

        #addition of two differnt points : P1!=P2
        if self.x != other.x:
            diff_y = other.y + self.y
            diff_x = other.x + self.x
            s = diff_y/diff_x                                                    #slope of the expanding line of the P1, P2
            x_3 = s**2 + s + self.x + other.x + self.a                           #x3 = s**2 + s + x1 + x2 + a
            y_3 = s * (self.x + x_3) + x_3 + self.y                              #y3 = s*(x1 + x3) + x3 + y1
            return self.__class__(x_3, y_3, self.a, self.b)
        
    
    def __rmul__(self, coefficient):                            #Use double-and-add algorithm (https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add)
        coef = coefficient
        G = self                                                #generator point
        product = self.__class__(None, None, self.a, self.b)    #if coefficient is 0. return infinity point
        i = 0
        j = 1
        while coef != 0:                                        # this can be shortened to "while coef:"
            i += 1
            if coef & 1 :                                       #if AND operate between coef and 0b1 is not 0, then product += G
                j += 1
                product += G
                if coef == 1 : break                            #if coef==1, the loop ends without calculating the following calc
            G += G
            coef >>= 1                                          #A>>=B : shift bit of "A" to right by "B" and reassign to "A". this remove right bit of binary coef
                                                                #thus loop run (digits of binart coef - 1) times. and it sames as log_2(coef)
        return product

class S163Field(FieldElement):

    def __init__(self, num, m=None, p=None):
        super().__init__(num, m=m163, p=p163)                    #Inherit num, prime from FieldElement

    def __repr__(self):
        return '{:x}'.format(self.num).zfill(41)                #{:x}.format(num) changes num to hexadecimal number. zfill(41) pad leading zeros to make 41 digits

class S163Point(Point_for_sect):
    
    def __init__(self, x, y, a, b):
        if type(x) == int:
            super().__init__(x=S163Field(x), y=S163Field(y), a=S163Field(a), b=S163Field(b))    #a,b of Weierstrass equation are also element of binary field
        else:
            super().__init__(x=x, y=y, a=a, b=b)                #if x is infinity point(x=None), do not use S163Field(x), just pass x as it is

    def __rmul__(self, coefficient):
        coef = coefficient % q                                  #since nG=0, using coefficient % N reduce calculation process.
        return super().__rmul__(coef)

    def verify(self, z, sig):
        s_inv = pow(sig.s, q-2, q)                              #pow(a,b,c) is difined as (a^b)%c, N is order of the group and also prime number.
        u = z * s_inv % q                                       #u = z/s
        v = sig.r * s_inv % q                                   #v = r/x
        R = u * G + v * self                                    #uG + vP = R
        return R.x.num == sig.r                                 #uG+vP = R, So do x value of R and r match?

#################################
#G = S163Point(Ux,Uy,a163,b163)                                            #set the generator point

from memo import deterministic_K
from unittest import TestCase

N = 10000
C = 100000
a = a163
m = m163

mu = (-1)**(1-a)
lamda = []
f = []
eta = []
h = []

def tau(A):
    A0 = FieldElement(A[0],m,p163)
    A1 = FieldElement(A[1],m,p163)
    new_A0 = A0 * A0
    new_A1 = A1 * A1
    B = np.array([new_A0.num,new_A1.num])
    return B

# def tau(A):
#     # A0 = FieldElement(A[0],m,p163)
#     # A1 = FieldElement(A[1],m,p163)
#     # new_A0 = A0 * A0
#     # new_A1 = A1 * A1
#     B = np.array([A[0]*A[0],A[1]*A[1]])
#     return B

#https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
class ECCTest(TestCase):
    """
    The following algorithm computes the scalar multiple nP on the Koblitz curve E(a,b) over GF(2m).
    The average number of elliptic additions and subtractions is at most ∼ 1 + (m/3), and is at most ∼
    m/3 with probability at least 1 – 2^(5–C) (when C > 5 integer)
    """
    def sign(self):
        print(Ux,Uy)
        #part 1
        for i in range(2):
            
            n_prime = math.floor(N/a**( a-C + (m-9)/2 ))
            g_prime = s[i] * n_prime
            h_prime = math.floor(g_prime/2**m)
            j_prime = V * h_prime
            l_prime = round( (g_prime + j_prime) / 2**((m+5)/2) )
            lamda.append(l_prime/2**C)
            f.append(round(lamda[i]))
            eta.append(lamda[i]-f[i])
            h.append(0)

        #part 2
        Eta = 2*eta[0] + mu*eta[1]

        #part 3
        if Eta >= 1 :
            if eta[0] - 3 * mu * eta[1] < -1 : h[1] = mu
            else : h[0] = 1
        else : 
            if eta[0] + 4 * mu * eta[1] >= 2 : h[1] = mu

        #part 4
        if Eta < -1 :
            if eta[0] - 3 * mu * eta[1] >= 1 : h[1] = -1 * mu
            else : h[0] = -1
        else:
            if eta[0] + 4 * mu * eta[1] < -2:
                h[1] = -1 * mu

        #part 5
        q0 = f[0] + h[0]

        #part 6
        q1 = f[1] + h[1]

        #part 7
        r0 = N - (s[0] + mu * s[1])*q0 - 2*s[1]*q1

        #part 8
        r1 = s[1]*q0 - s[0]*q1

        #part 9
        Q = np.array([0,0])

        #part 10 
        P0 = np.array([Ux,Uy])

        time = 0
        #part 11
        while r0 != 0 or r1 != 0:
            time += 1
            if r0%2 == 1 :
                u = 2 - (r0 - 2*r1%4)
                r0 = r0 - u
                if u == 1  : Q = Q + P0
                if u == -1 : Q = Q - P0
            P0 = tau(P0)
            (r0, r1) = (r1 + mu*r0/2, -1*r0/2)

        print(time)
        print(Q)
        L1 = 8854360699869281003174844452691410143827669531635
        L2 = 7303236429070656088361553180575281572993186095398
        print((L1-Q[0])/L1,(L2-Q[1])/L2)


from helper import run
run(ECCTest('sign'))





