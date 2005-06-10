import pickle

def encode_long(l):
   if l == 0:
       return '\x00'

   return ''.join(reversed(pickle.encode_long(l)))

def decode_long(s):
   return pickle.decode_long(''.join(reversed(s)))
