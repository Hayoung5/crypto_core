def mul(g, coefficient):
    coef = coefficient
    G = g               #generator point
    product = 0    #if coefficient is 0. return infinity point
    loop=1
    while coef != 0:        #this can be shortened to "while coef:"
        if coef & 1 :       #if AND operate between coef and 0b1 is not 0, then product += G
            product += G
            if coef == 1 : break
        G += G
        coef >>= 1          # A>>=B : shift bit of "A" to right by "B" and reassign to "A" 
        print(coef,G,product)
    return product


print(mul(122,11111))