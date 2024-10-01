from line_profiler import profile
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from utils import dilithium,ecc, rsaalg 
from Crypto.PublicKey import ECC, RSA

@profile
def dil(level):
    ec.generate_private_key(ec.BrainpoolP256R1())
    ec.generate_private_key(ec.BrainpoolP384R1())
    ec.generate_private_key(ec.BrainpoolP512R1())

    ec.generate_private_key(ec.SECP256R1())
    ec.generate_private_key(ec.SECP384R1())
    ec.generate_private_key(ec.SECP521R1())



for _ in range(1000):
    dil(1)
