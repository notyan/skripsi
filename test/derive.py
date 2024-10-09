from cryptography.hazmat.primitives.asymmetric import ec
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS

key = ECC.generate(curve='p256')
print(int(key.d))

# secret_key = ec.generate_private_key(ec.BrainpoolP256R1())
# private_number= secret_key.private_numbers()
# public_key = secret_key.public_key()
# public_number = public_key.public_numbers()
# #print(private_number.private_value)
# print(public_number) 

print(ec.derive_private_key(int(key.d), ec.SECP256R1()))

