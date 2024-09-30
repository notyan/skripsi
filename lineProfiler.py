from line_profiler import profile
from Crypto.PublicKey import ECC
from utils import dilithium, ecc, rsaalg , pem
import subprocess




@profile
def dil(level):
    ecc.keygen(1)
    ecc.keygen(2)
    ecc.keygen(3)
    ECC.generate(curve='p521')
    ECC.generate(curve='p384')
    ECC.generate(curve='p256')
    

# @profile
# def ecdsa():
#     ecc.keygen(2)

# @profile
# def rsaaa():
#     rsaalg.keygen(1)



for _ in range(100):
    dil(1)
