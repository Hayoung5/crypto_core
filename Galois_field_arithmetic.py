# ref https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture7.pdf

# from BitVector import *
# def gf_divide(num, mod, n):
#     """Using the arithmetic of the Galois Field GF(2^n), this function divides
#     the bit pattern ’num’ by the modulus bit pattern ’mod’
#     """
#     if mod.length() > n+1:
#         raise ValueError("Modulus bit pattern too long")
#     quotient = BitVector( intVal = 0, size = num.length() )
#     remainder = num.deep_copy()
#     i = 0
#     while 1:
#         i = i+1
#         if (i==num.length()): break
#         mod_highest_power = mod.length() - mod.next_set_bit(0) - 1
#         if remainder.next_set_bit(0) == -1:
#             remainder_highest_power = 0
#         else:
#             remainder_highest_power = remainder.length() - remainder.next_set_bit(0) - 1
#         if (remainder_highest_power < mod_highest_power) or int(remainder)==0:
#             break
#     else:
#         exponent_shift = remainder_highest_power - mod_highest_power
#         quotient[quotient.length() - exponent_shift - 1] = 1
#         quotient_mod_product = mod.deep_copy()
#         quotient_mod_product.pad_from_left(remainder.length() - mod.length() )
#         quotient_mod_product.shift_left(exponent_shift)
#         remainder = remainder ^ quotient_mod_product
#     if remainder.length() > n:
#         remainder = remainder[remainder.length()-n:]
#     return quotient, remainder


# def gf_multiply(a, b):
#     """Using the arithmetic of the Galois Field GF(2^n), this function multiplies
#     the bit pattern ’a’ by the bit pattern ’b’.
#     """
#     a_highest_power = a.length() - a.next_set_bit(0) - 1
#     b_highest_power = b.length() - b.next_set_bit(0) - 1
#     result = BitVector( size = a.length()+b.length() )
#     a.pad_from_left( result.length() - a.length() )
#     b.pad_from_left( result.length() - b.length() )
#     for i,bit in enumerate(b):
#         if bit == 1:
#             power = b.length() - i - 1
#             a_copy = a.deep_copy()
#             a_copy.shift_left( power )
#             result ^= a_copy
#     return result

# def gf_multiply_modular(a, b, mod, n):
#     """
#     Using the arithmetic of the Galois Field GF(2^n), this function returns ’a’
#     divided by ’b’ modulo the bit pattern in ’mod’.
#     """
#     a_copy = a.deep_copy()
#     b_copy = b.deep_copy()
#     product = gf_multiply(a_copy,b_copy)
#     quotient, remainder = gf_divide(product, mod, n)
#     return remainder

# def gf_MI(num, mod, n):
#     """
#     Using the arithmetic of the Galois Field GF(2^n), this function returns the
#     multiplicative inverse of the bit pattern ’num’ when the modulus polynomial
#     is represented by the bit pattern ’mod’.
#     """
#     NUM = num.deep_copy(); MOD = mod.deep_copy()
#     x = BitVector( size=mod.length() )
#     x_old = BitVector( intVal=1, size=mod.length() )
#     y = BitVector( intVal=1, size=mod.length() )
#     y_old = BitVector( size=mod.length() )
#     while int(mod):
#         quotient, remainder = gf_divide(num, mod, n)
#         num, mod = mod, remainder
#         x, x_old = x_old ^ gf_multiply(quotient, x), x
#         y, y_old = y_old ^ gf_multiply(quotient, y), y
#     if int(num) != 1:
#         return "NO MI. However, the GCD of ", str(NUM), " and ", str(MOD), " is ", str(num)
#     else:
#         quotient, remainder = gf_divide(x_old ^ MOD, MOD, n)
#     return remainder

# mod = BitVector( bitstring = bin(55)[2:] )
# a = BitVector( bitstring = bin(31)[2:] )
# b = BitVector( bitstring = bin(26)[2:] )
# result = gf_multiply_modular(a, b, mod, 5)
# print(result)
# print("\nMI of %s is: %s" % (str(a), str(result)))
# a = BitVector( bitstring = "10010101" )
# result = gf_MI( a, mod, 8 )
# print("\nMI of %s is: %s" % (str(a), str(result)))
# a = BitVector( bitstring = "00000000" )
# result = gf_MI( a, mod, 8 )
# print("\nMI of %s is: %s" % (str(a), str(result)))


# The addition and subtraction in GF(2m) is same as XOR.
# There are several wat to define division in GF(2m)
# Divide1() use extended Euclidean division
# Divide2() use Fermat's little theorm, Divide2() is faster than Divide1()

from re import X


# p163 = 0x800000000000000000000000000000000000000c9
# m163 = 163
# a163=1; b163=1                                      # this will be given as field element of GF(2m) 
# q = 0x4000000000000000000020108A2E0CC0D99F8A5EF     # number of element of the field. same as N
# qlen = 163
# Ux = 0x79AEE090DB05EC252D5CB4452F356BE198A4FF96F
# Uy = 0x782E29634DDC9A31EF40386E896BAA18B53AFA5A3

m163 = 2
p163 = 7

print(hex(2**163-1))

def left(x,y) :
    y2 = my_pow(y,2)
    xy = Multiply(x,y,m163)
    result = y2 ^ xy
    result = gf_divide(result, p163,m163)
    return result[1]

def right(x, y):
    x2 = my_pow(x,2)
    x3 = my_pow(x,3)
    result = x3 ^ x2 ^ 1
    result = gf_divide(result, p163,m163)
    return result[1]


def gf_multiply(A,B,m):
    # a * b = r of GF(2^m)
    if A > B :
        a,b = (A,B)
    else : a,b = (B,A)
    binary_b = bin(b)[2:]
    blen = len(binary_b)
    result = 0
    for i, bit in enumerate(binary_b):
        n = blen -i -1
        if bit == '1':
            shifted_a = a << n
            result ^= shifted_a
    return result

def gf_divide(a, b, m):
    # repeat of euclidean divde
    # a = b*(2^d + 2^(d-1) +.. 2^(0)) + remainder
    # (2^d + 2^(d-1) +.. 2^(0)) = quotient 	
    result = a
    q = 0
    while 1:
        n = len(bin(result))-len(bin(b)) 
        if n < 0 : break
        q += 1<<n
        shifted_b = b << n
        result ^= shifted_b
        if result == 0 : break
    return q, result

def Multiply(A,B,m):
    result = gf_multiply(A,B,m)
    q, result = gf_divide(result,p163,m)
    return result

def inverse(a,p,m):
    t = 0
    r = p
    newt = 1
    newr = a

    while 1:
        q, remainder = gf_divide(r, newr, m)
        if remainder == 0 : break
        r = newr
        newr = remainder
        t,newt = newt ,t^ gf_multiply(q,newt,m)

    result = newt
    return result

def Divide1(a,b): #using inverse (Extended Euclidean Division)
    # a / b = a * (1/b)
    b_inv = inverse(b,p163,m163)
    result = Multiply(a,b_inv,m163)
    q, result = gf_divide(result,p163,m163)
    return result

def my_pow(a, exponent):
    n = exponent % (2**m163 -1) #this allow negative exponent and fast calc using Fermat's Little Theorem 1 = a^(p-1))
    result = 1
    for i in range(n):
        result = Multiply(result, a,m163)
    return result

def my_pow2(a, exponent):
    n = exponent % (2**m163 -1) #this allow negative exponent and fast calc using Fermat's Little Theorem 1 = a^(p-1))
    result = 1
    x = a                      
    if n == 0 :                                         #Using square-and-multiply algorithm
        return result
    else :
        while n > 1:
            if n & 1 :                                      # if odd
                result = Multiply(result,x,m163)
                x = Multiply(x,x,m163)
            else :
                x = Multiply(x,x,m163)
            n >>= 1
        return Multiply(x,result,m163)


#can define division of the finite field using pow (Fermat's Little Theorem )
def Divide2(a, b):
    #return a/b =a*b^(p-2)
    return Multiply(a, my_pow2(b,(2**m163-2)),m163)


def new_point(x,y):
    s = Divide1(y,x) ^ x
    x2 = Multiply(x,x,m163)
    x3 = x2 ^ Divide1(1,x2)
    y3 = x2 ^ Multiply(s,x3,m163) ^ x3
    return x3,y3

def new_point2(x,y):
    x_inv = inverse(x,p163,m163)
    s = Multiply(y,x_inv,m163) ^ x
    x2 = Multiply(x,x,m163)
    x2_inv = inverse(x2,p163,m163)
    x3 = x2 ^ x2_inv
    y3 = x2 ^ Multiply(s,x3,m163) ^ x3
    return x3,y3


def check(x,y):
    x_inv = inverse(x,p163,m163)
    print(x_inv)
    print(Divide2(1,x))

a = gf_divide(5,p163,m163)
print(a)
#print(Multiply(Ux,Ux,m163))
#print(Multiply(Uy,Uy,m163))
# check(Ux,Uy)
# x3, y3 = new_point2(Ux,Uy)
# print(left(x3,y3))
# print(right(x3,y3))
# x3, y3 = new_point(Ux,Uy)
# print(left(x3,y3))
# print(right(x3,y3))
# print(x3,y3)
# x3, y3 = new_point2(Ux,Uy)
# print(x3,y3)


#x3,t3 = 0x47e81038546456d77ec582fc585808924298e484c 0x1b474388d181eb0dfd4c63e3eb1819de00a948036

# result = my_pow(4,-2)
# print("result", result)

# result = inverse(4,p,m)
# result = Multiply(result,result,m)
# print("result", result)
#(010fffd76d683007b4c9e299b1e8dedad5e3ea736, 4729bce755cc74eecc0d0cccf106bcb90d8e9349e) is not on the elliptic curve