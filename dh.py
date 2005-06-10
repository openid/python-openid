import pickle

def encode_long(l):
   if l == 0:
       return '\x00'

   return ''.join(reversed(pickle.encode_long(l)))

def decode_long(s):
   return pickle.decode_long(''.join(reversed(s)))

def power_mod(base, exp, modulus):
    square = base % modulus
    result = 1
    while exp > 0:
        if exp & 1 == 1:
            result = (result * square) % modulus
        exp /= 2
        
        square = (square * square) % modulus
    
    return result
