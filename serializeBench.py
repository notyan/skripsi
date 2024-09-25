from operator import truediv
from utils import kyber, pem, dilithium, rsaalg, ecc
import time
import timeit

level = 1
repetition = 1000

ecdsa_ssk, ecdsa_vk = ecc.keygen(level)
_, pk = ecc.keygen(level)
print((timeit.timeit(lambda: pem.serialize(pk, 1) , number=repetition)))

start_time = time.time_ns()
pem.serialize(pk, 1)
print((time.time_ns() - start_time)/1000000)
