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


### DH Constants
DEFAULT_MOD = 155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443L

DEFAULT_GEN = 2
