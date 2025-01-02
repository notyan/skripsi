from anyio import key
from utils import ds, kem, pem   
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

from utils.pem import serialize


sk, pk = ds.keygen(1,False, True)
skPD = sk.private_numbers()
# print(len(pem.serializeDer(sk, 0)))
# print(len(pem.serializeDer(pk, 1)))
#print(len(str(skPD.public_numbers)))

# print(len(str(skPD.public_numbers.n)))
# print(len(str(skPD.d)))
print(skPD.p.bit_length())
print(skPD.public_numbers.n.bit_length())

sk, pk = ds.keygen(3,False, False)
eccSK = sk.private_numbers()
print(eccSK.private_value.bit_length())

q = 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377
print(q.bit_length())