def shift_right(num, bits):
    num >>= bits
    return num

def rotate_left(num, bits):
    num = "{0:b}".format(num).zfill(32)
    rotl = num[bits:] + num[:bits]
    return int(rotl,2)                                          #do not forget add ",2" to change binary to decimal

def rotate_right(num, bits):
    num = "{0:b}".format(num).zfill(32)
    rotr = num[-bits:] + num[:-bits]
    return int(rotr,2)

def rho0(X):                                                    #small sigma0 function, changed to rho to avoid confusion.
    rho = rotate_right(X,7) ^ rotate_right(X,18) ^ shift_right(X,3)
    return rho

def rho1(X):
    rho = rotate_right(X,17) ^ rotate_right(X,19) ^ shift_right(X,10)
    return rho

def Sigma0(X):
    sigma = rotate_right(X,2) ^ rotate_right(X,13) ^ rotate_right(X,22)
    return sigma

def Sigma1(X):
    sigma = rotate_right(X,6) ^ rotate_right(X,11) ^ rotate_right(X,25)
    return sigma

def Choose(X, Y, Z):
    ch = (X & Y) ^ ((~X) & Z)
    return ch

def Majority(X, Y, Z):
    maj = (X & Y) ^ (X & Z) ^ (Y & Z)
    return maj