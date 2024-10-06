from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS
from utils import ecc, pem

key = ECC.generate(curve='p256')
key2 = ECC.generate(curve='p256')

#rsa_key = RSA.generate(3072)

key = ECC.generate(curve='p256')
key2 = ECC.generate(curve='p256') 

key = ECC.generate(curve='p256')
sk_bytes = key.export_key(format="DER")
pk_bytes = key.public_key().export_key(format="DER")

sk_bytes2 = key2.export_key(format="DER")
pk_bytes2 = key2.public_key().export_key(format="DER")

#print(sk_bytes)
sk = pem.der_to_key(sk_bytes,0 )
print(ecc.sign(1, pk_bytes2, sk))


