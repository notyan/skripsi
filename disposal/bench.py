from operator import truediv
from utils import kyber, pem, dilithium, rsaalg, ecc
import requests
import time

level_range = 2
iteration = 10
#algorithms =  ["RSA", "ECC", "PQ"]
algorithms =  [ "PQ" , "ECC"]
#1000000  = ms, 1000000000 = second
unit = 1000000 

print("BENCHMARKING KEM KEYGEN AND SIGN")
for alg in algorithms:
    print(f'ALGORITMA {alg}  \nLevel\tTime')
    for level in range(1,level_range):
        running_time= list()
        rsa_ssk, rsa_vk = rsaalg.keygen(level)
        pq_ssk, pq_vk = dilithium.keygen(level)
        ecdsa_ssk, ecdsa_vk = ecc.keygen(level)
        for i in range(iteration):
            if alg == "PQ":
                start_time = time.time_ns()
                sk, pk = kyber.keygen(level)
                dilithium.sign(level, pk, pq_ssk)
                running_time.append(time.time_ns() - start_time)
            else:
                if alg == "ECC":
                    #1. Generate KEMPAIR
                    start_time = time.time_ns()
                    _, pk = ecc.keygen(level)
                    kem_keygen = time.time_ns() - start_time

                    pk_bytes = pem.serializeDer(pk, 1)
                    start_time = time.time_ns()
                    ecc.sign(level, pk_bytes, ecdsa_ssk)
                elif alg == "RSA":
                    #1. Generate KEMPAIR
                    start_time = time.time_ns()
                    _, pk = rsaalg.keygen(level)
                    kem_keygen = time.time_ns() - start_time

                    pk_bytes = pem.serializeDer(pk, 1)
                    start_time = time.time_ns()
                    rsaalg.sign(level, pk_bytes, rsa_ssk)
                else:
                    print("Algorithm outside Scope")

                sign_time = time.time_ns() - start_time
                running_time.append(sign_time + kem_keygen)     

        avg = (sum(running_time)/len(running_time))/unit
        print(f'{level} \t{ avg:.4f} ms')


# print("\nBENCHMARKING VERIFY, ENCAPSULATION, SIGN")
# for alg in algorithms:
#     print(f'ALGORITMA {alg}  \nLevel\tTime')
#     for level in range(1,level_range):
#         #PQ BUILTUP
#         pq_ssk, pq_vk = dilithium.keygen(level)
#         _, pq_pk = kyber.keygen(level)
#         pq_signature = dilithium.sign(level, pq_pk, pq_ssk)

#         #PREQUANTUM BUILTUP
#         rsa_sk, rsa_pk = rsaalg.keygen(level)
#         pk_bytes = pem.serializeDer(rsa_pk, 1)
#         rsa_ssk, rsa_vk = rsaalg.keygen(level)
#         rsa_signature = rsaalg.sign(level, pk_bytes, rsa_ssk)

#         #ECCBUILTUP
#         ecc_sk, ecc_pk = ecc.keygen(level)
#         pk_bytes = pem.serializeDer(ecc_pk, 1)
#         ecdsa_ssk, ecdsa_vk = ecc.keygen(level)
#         ecdsa_signature = ecc.sign(level, pk_bytes, ecdsa_ssk)

        
#         running_time= list()
#         for i in range(iteration):
#             if alg == "PQ":
#                 start_time = time.time_ns()
#                 is_valid = dilithium.verif(level, pq_pk, pq_signature, pq_vk)       #1. Verify kem pub
#                 c, K = kyber.encap(level, pq_pk)                                    #2. Encap K
#                 new_signature = dilithium.sign(level, c, pq_ssk)                    #3. Sign c
#             elif alg == "ECC":
#                 pk = pem.der_to_key(pk_bytes, 1)
#                 c_temp, K = ecc.encap(level, pk)
#                 c_bytes = pem.serializeDer(c_temp, 1)

#                 start_time = time.time_ns()
#                 is_valid = ecc.verif(level, pk_bytes, ecdsa_signature, ecdsa_vk)
#                 c, K = ecc.encap(level, pk)
#                 signature = ecc.sign(level, c_bytes, ecdsa_ssk)   
#             else:
#                 pk = pem.der_to_key(pk_bytes, 1)
#                 start_time = time.time_ns()
#                 is_valid = rsaalg.verif(level, pk_bytes, rsa_signature, rsa_vk)
#                 c, K = rsaalg.encap(level, pk)
#                 signature = rsaalg.sign(level, c, rsa_ssk)
#             running_time.append(time.time_ns() - start_time)   

#         avg = (sum(running_time)/len(running_time))/unit
#         print(f'{level} \t{ avg:.4f} ms')


print("\nBENCHMARKING Verify and Decaps")
for alg in algorithms:
    print(f'ALGORITMA {alg} \nLevel\tTime')
    for level in range(1,level_range):
        #PQ BUILTUP
        pq_ssk, pq_vk = dilithium.keygen(level)
        pq_sk, pq_pk = kyber.keygen(level)
        pq_c, pq_K = kyber.encap(level, pq_pk) 
        pq_signature = dilithium.sign(level, pq_c, pq_ssk)

        #PRE-Q BUILTUP
        rsa_sk, rsa_pk = rsaalg.keygen(level)
        rsa_c, rsa_K = rsaalg.encap(level, rsa_pk)
        rsa_ssk, rsa_vk = rsaalg.keygen(level)
        rsa_signature = rsaalg.sign(level, rsa_c, rsa_ssk)

        #EC BUILTUP
        ecc_sk, ecc_pk = ecc.keygen(level)
        ecdsa_ssk, ecdsa_vk = ecc.keygen(level)
        
        pk_bytes = pem.serializeDer(ecc_pk, 1)

        ecc_c, ecc_K = ecc.encap(level, ecc_pk)
        c_bytes = pem.serializeDer(ecc_c, 1)

        ecdsa_signature = ecc.sign(level, c_bytes, ecdsa_ssk)

        running_time= list()

        for i in range(iteration):
            if alg == "PQ":
                start_time = time.time_ns()
                is_valid = dilithium.verif(level, pq_c, pq_signature, pq_vk)
                kyber.decap(level, pq_sk, pq_c )
            elif alg == "ECC":
                start_time = time.time_ns()
                is_valid = ecc.verif(level, c_bytes, ecdsa_signature, ecdsa_vk)
                ecc.decap(level, ecc_sk, ecc_c)    
            else:
                start_time = time.time_ns()
                is_valid = rsaalg.verif(level, rsa_c, rsa_signature, rsa_vk)
                rsaalg.decap(level, rsa_sk, rsa_c)

            #Append into list, to get another data insight
            running_time.append(time.time_ns() - start_time)

        avg = (sum(running_time)/len(running_time))/unit
        print(f'{level} \t{ avg:.4f} ms')
        