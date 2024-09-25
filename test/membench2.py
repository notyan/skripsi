from operator import truediv
import profile
from utils import kyber, pem, dilithium, rsaalg, ecc
from memory_profiler import profile, memory_usage
import gc

level_range = 3
iteration = 1
algorithms =  ["RSA", "ECC", "PQ"]

#@profile(precision=5)
def signKem(level):
    #IGNORED
    pq_ssk, pq_vk = dilithium.keygen(level)
    ecdsa_ssk, ecdsa_vk = ecc.keygen(level)
    rsa_ssk, rsa_vk = rsaalg.keygen(level)

    #PQ CODE BENCHMARK
    sk, pk = kyber.keygen(level)
    dilithium.sign(level, pk, pq_ssk)

    #PRE-Q Benchmark
    sk, pk = rsaalg.keygen(level)
    pk_bytes = pem.serializeDer(pk, 1)
    ecc.sign(pk_bytes, ecdsa_ssk)           #ECC
    rsaalg.sign(pk_bytes, rsa_ssk)          #RSA
    
    del pq_ssk, pq_vk,ecdsa_ssk, ecdsa_vk ,rsa_ssk, rsa_vk , sk, pk , pk_bytes
    gc.collect()

# for level in range(2,level_range):
#     signKem(level)

memory_usage((signKem, (1)))



from utils import kyber
kyber.keygen(1)
