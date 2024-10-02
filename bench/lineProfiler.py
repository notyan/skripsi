from line_profiler import profile
from cryptography.hazmat.primitives.asymmetric import ec
from Crypto.PublicKey import ECC


from utils import ecc


@profile
def dil(level):
    ec.generate_private_key(ec.BrainpoolP256R1())
    ec.generate_private_key(ec.BrainpoolP384R1())
    ec.generate_private_key(ec.BrainpoolP512R1())
    ecc.keygen(1)
    ecc.keygen(2)
    ecc.keygen(3)



for _ in range(1000):
    dil(1)
