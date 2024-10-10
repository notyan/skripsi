from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS

key = ECC.generate(curve='p256')
print(key.d)



