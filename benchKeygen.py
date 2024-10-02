from line_profiler import profile
from cryptography.hazmat.primitives.asymmetric import ec
from utils import ecc, rsaalg, dilithium, kyber


@profile
def keygenBench():
    kyber.keygen(1)
    dilithium.keygen(1)
    ecc.keygen(1)
    rsaalg.keygen(1)

    kyber.keygen(2)
    dilithium.keygen(2)
    ecc.keygen(2)
    rsaalg.keygen(2)
    
    kyber.keygen(3)
    dilithium.keygen(3)
    ecc.keygen(3)
    rsaalg.keygen(3)

    



for _ in range(1000):
    keygenBench()
