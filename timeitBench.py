from operator import truediv

from fastapi.background import P
from utils import kyber, pem, dilithium, rsaalg, ecc
import timeit
from functools import partial


level_range = 4
iteration = 1000
algorithms =  ["RSA", "ECC", "PQ"]
#algorithms =  [ "RSA", "PQ", "ECC"]
#1000000  = ms, 1000000000 = second
unit = 1000000 

def firstBench(alg, sign_key, level, repetition):
    if alg == "PQ":
        keygeneration = partial(kyber.keygen, level)
        _, pk_bytes = kyber.keygen(level)
        signing = partial(dilithium.sign, level, pk_bytes, sign_key)
    elif alg == "ECC":
        keygeneration = partial(ecc.keygen, level)
        _, pk = ecc.keygen(level)
        pk_bytes = pem.serializeDer(pk, 1)
        signing = partial(ecc.sign,level, pk_bytes, sign_key)
    elif alg == "RSA":
        keygeneration = partial(rsaalg.keygen,level)
        _, pk = rsaalg.keygen(level)
        pk_bytes = pem.serializeDer(pk, 1)
        signing = partial(rsaalg.sign,level, pk_bytes, sign_key)

    keygen_time = timeit.timeit(keygeneration , number=repetition)
    sign_time = timeit.timeit(signing , number=repetition)
    return ((keygen_time + sign_time)/iteration)*1000


print("BENCHMARKING KEM KEYGEN AND SIGN")
for alg in algorithms:
    print(f'ALGORITMA {alg}  \nLevel\tTime')
    for level in range(1,level_range):
        if alg == "PQ":
            sign_key, _ = dilithium.keygen(level)
        elif alg == "ECC":
            sign_key, _ = ecc.keygen(level)
        elif alg == "RSA":
            sign_key, _ = rsaalg.keygen(level)

        print(firstBench(alg, sign_key, level, iteration))


def secondBench(alg, level, pk_bytes, sign_key, signature,vk, repetition):
    if alg == "PQ":
        verification = partial(dilithium.verif, level,pk_bytes,signature,vk)
        encapsulation =  partial(kyber.encap, level, pk_bytes)
        c_bytes, _ = kyber.encap(level, pk_bytes)
        signing = partial(dilithium.sign, level, c_bytes, sign_key)

    elif alg == "ECC":
        pk = pem.der_to_key(pk_bytes, 1)
        c, _ = ecc.encap(level, pk)
        c_bytes = pem.serializeDer(c, 1)

        verification = partial(ecc.verif, level, pk_bytes, signature, vk)
        encapsulation =  partial(ecc.encap, level, pk)
        signing = partial(ecc.sign, level, c_bytes, sign_key)
        
    elif alg == "RSA":
        pk = pem.der_to_key(pk_bytes, 1)
        c_bytes, _ = rsaalg.encap(level, pk)
        verification = partial(rsaalg.verif, level,pk_bytes,signature, vk)
        encapsulation =  partial(rsaalg.encap, level, pk)
        signing = partial(rsaalg.sign, level, c_bytes, sign_key)

    verification_time = timeit.timeit(verification , number=repetition)
    encapsulation_time = timeit.timeit(encapsulation , number=repetition)
    sign_time = timeit.timeit(signing , number=repetition)
    return ((verification_time + encapsulation_time + sign_time)/iteration)*1000


print("\nBENCHMARKING VERIFY, ENCAPSULATION, SIGN")
for alg in algorithms:
    print(f'ALGORITMA {alg}  \nLevel\t\tTime')
    for level in range(1,level_range):
        if alg == "PQ":
            sign_key, vk = dilithium.keygen(level)
            _, pk_bytes = kyber.keygen(level)
            signature = dilithium.sign(level, pk_bytes, sign_key)
        elif alg == "ECC":
            _, pk = ecc.keygen(level)
            pk_bytes = pem.serializeDer(pk, 1)
            sign_key, vk = ecc.keygen(level)
            signature = ecc.sign(level, pk_bytes, sign_key)
        elif alg == "RSA":
            _, pk = rsaalg.keygen(level)
            pk_bytes = pem.serializeDer(pk, 1)
            sign_key, vk = rsaalg.keygen(level)
            signature = rsaalg.sign(level, pk_bytes, sign_key)

        print(secondBench(alg, level, pk_bytes, sign_key, signature,vk, iteration))
        


# print("\nBENCHMARKING Verify and Decaps")
# for alg in algorithms:
#     print(f'ALGORITMA {alg} \nLevel\tTime')
#     for level in range(1,level_range):
#         #PQ BUILTUP
#         pq_ssk, pq_vk = dilithium.keygen(level)
#         pq_sk, pq_pk = kyber.keygen(level)
#         pq_c, pq_K = kyber.encap(level, pq_pk) 
#         pq_signature = dilithium.sign(level, pq_c, pq_ssk)

#         #PRE-Q BUILTUP
#         rsa_sk, rsa_pk = rsaalg.keygen(level)
#         rsa_c, rsa_K = rsaalg.encap(rsa_pk)

#         #RSA BUILTUP
#         rsa_ssk, rsa_vk = rsaalg.keygen(level)
#         rsa_signature = rsaalg.sign(rsa_c, rsa_ssk)

#         #EC BUILTUP
#         ecdsa_ssk, ecdsa_vk = ecc.keygen(level)
#         ecdsa_signature = ecc.sign(rsa_c, ecdsa_ssk)

#         running_time= list()

#         for i in range(iteration):
#             if alg == "PQ":
#                 start_time = time.time_ns()
#                 is_valid = dilithium.verif(level, pq_c, pq_signature, pq_vk)
#                 K = kyber.decap(level, pq_pk, pq_c )
#             elif alg == "ECC":
#                 start_time = time.time_ns()
#                 is_valid = ecc.verif(rsa_c, ecdsa_signature, ecdsa_vk)
#                 K = rsaalg.decap(rsa_sk, rsa_c)    
#             else:
#                 start_time = time.time_ns()
#                 is_valid = rsaalg.verif(rsa_c, rsa_signature, rsa_vk)
#                 K = rsaalg.decap(rsa_sk, rsa_c)
#             #Append into list, to get another data insight
#             running_time.append(time.time_ns() - start_time)

#         avg = (sum(running_time)/len(running_time))/unit
#         print(f'{level} \t{ avg:.4f} ms')
        