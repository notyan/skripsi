from operator import truediv
from utils import kyber, pem, dilithium, rsaalg, ecc
import requests
import time

level_range = 2
iteration = 1
algorithms =  ["RSA", "ECC", "PQ"]

print("BENCHMARKING KEM KEYGEN AND SIGN")
for alg in algorithms:
    for level in range(1,level_range):
        running_time= list()
        rsa_ssk, rsa_vk = rsaalg.keygen(level)
        pq_ssk, pq_vk = dilithium.keygen(level)
        ecdsa_ssk, ecdsa_vk = ecc.keygen(level)
        for i in range(iteration):
            if alg == "PQ":
                
                start_time = time.time_ns()
                sk, pk = kyber.keygen(level)
                signature = dilithium.sign(level, pk, pq_ssk)
                running_time.append(time.time_ns() - start_time)   

            else:
                #1. Generate KEMPAIR
                start_time = time.time_ns()
                sk, pk = rsaalg.keygen(level)           
                kem_keygen = time.time_ns() - start_time

                pk_bytes = pem.serializeDer(pk, 1)
                #2. Sign 
                if alg == "ECC":
                    tart_time = time.time_ns()
                    signature = ecc.sign(pk_bytes, ecdsa_ssk)
                    sign_time = time.time_ns() - start_time
                elif alg == "RSA":
                    start_time = time.time_ns()
                    signature = rsaalg.sign(pk_bytes, rsa_ssk)
                    sign_time = time.time_ns() - start_time
                else:
                    print("Algorithm outside Scope")

                running_time.append(sign_time + kem_keygen)     

        avg = (sum(running_time)/len(running_time))/1000000000
        print(f'Algoritma {alg} level {level} took { avg:.7f} s')


print("BENCHMARKING VERIFY, ENCAPSULATION, SIGN")
for alg in algorithms:
    for level in range(1,level_range):
        #PQ BUILTUP
        pq_ssk, pq_vk = dilithium.keygen(level)
        pq_sk, pq_pk = kyber.keygen(level)
        pq_signature = dilithium.sign(level, pq_pk, pq_ssk)

        #PREQUANTUM BUILTUP
        rsa_sk, rsa_pk = rsaalg.keygen(level)
        pk_bytes = pem.serializeDer(rsa_pk, 1)

        #RSABUILTUP
        rsa_ssk, rsa_vk = rsaalg.keygen(level)
        rsa_signature = rsaalg.sign(pk_bytes, rsa_ssk)

        #ECCBUILTUP
        ecdsa_ssk, ecdsa_vk = ecc.keygen(level)
        ecdsa_signature = ecc.sign(pk_bytes, ecdsa_ssk)

        running_time= list()
        for i in range(iteration):
            if alg == "PQ":
                start_time = time.time_ns()
                is_valid = dilithium.verif(level, pq_pk, pq_signature, pq_vk)       #1. Verify kem pub
                c, K = kyber.encap(level, pq_pk)                                    #2. Encap K
                new_signature = dilithium.sign(level, c, pq_ssk)                    #3. Sign c
                running_time.append(time.time_ns() - start_time)
            elif alg == "ECC":
                start_time = time.time_ns()
                is_valid = ecc.verif(rsa_pk, ecdsa_signature, ecdsa_vk)
                c, K = rsaalg.encap(rsa_pk)
                signature = ecc.sign(c, ecdsa_ssk)
                running_time.append(time.time_ns() - start_time)   
            else:
                start_time = time.time_ns()
                is_valid = rsaalg.verif(rsa_pk, rsa_signature, rsa_vk)
                c, K = rsaalg.encap(rsa_pk)
                signature = rsaalg.sign(c, rsa_ssk)
                running_time.append(time.time_ns() - start_time)   

        avg = (sum(running_time)/len(running_time))/1000000000
        print(f'Algoritma {alg} level {level} took { avg:.7f} s')


print("BENCHMARKING Verify and Decaps")
for alg in algorithms:
    for level in range(1,level_range):
        #PQ BUILTUP
        pq_ssk, pq_vk = dilithium.keygen(level)
        pq_sk, pq_pk = kyber.keygen(level)
        pq_c, pq_K = kyber.encap(level, pq_pk) 
        pq_signature = dilithium.sign(level, pq_c, pq_ssk)

        #PRE-Q BUILTUP
        rsa_sk, rsa_pk = rsaalg.keygen(level)
        rsa_c, rsa_K = rsaalg.encap(rsa_pk)

        #RSA BUILTUP
        rsa_ssk, rsa_vk = rsaalg.keygen(level)
        rsa_signature = rsaalg.sign(rsa_c, rsa_ssk)

        #EC BUILTUP
        ecdsa_ssk, ecdsa_vk = ecc.keygen(level)
        ecdsa_signature = ecc.sign(rsa_c, ecdsa_ssk)

        running_time= list()

        for i in range(iteration):
            if alg == "PQ":
                start_time = time.time_ns()
                is_valid = dilithium.verif(level, pq_c, pq_signature, pq_vk)
                K = kyber.decap(level, pq_pk, pq_c )
                running_time.append(time.time_ns() - start_time)   
            elif alg == "ECC":
                start_time = time.time_ns()
                is_valid = ecc.verif(rsa_c, ecdsa_signature, ecdsa_vk)
                K = rsaalg.decap(rsa_sk, rsa_c)
                running_time.append(time.time_ns() - start_time)    
            else:
                start_time = time.time_ns()
                is_valid = rsaalg.verif(rsa_c, rsa_signature, rsa_vk)
                K = rsaalg.decap(rsa_sk, rsa_c)
                running_time.append(time.time_ns() - start_time)   

        avg = (sum(running_time)/len(running_time))/1000000000
        print(f'Algoritma {alg} level {level} took { avg:.7f} s')