from utils import kyber, pem, dilithium, rsaalg, ecc
from utils.percentiles import percentiles
import timeit
from functools import partial
import numpy as np


level_range = 4
iteration = 100
algorithms =  ["RSA", "ECC", "PQ"]
#algorithms =  ["ECC", "PQ"]
#Timeit output are in second, multiply by 1000 to convert to ms
unit = 1000


def secondBench(alg, level, pk_bytes, sign_key, signature,vk, repetition):
    recurrence= int(repetition/10)
    if alg == "PQ":
        verification = partial(dilithium.verif, level,pk_bytes,signature,vk)    #Verified
        encapsulation =  partial(kyber.encap, level, pk_bytes)
        c_bytes, _ = kyber.encap(level, pk_bytes)
        signing = partial(dilithium.sign, level, c_bytes, sign_key)

    elif alg == "ECC":
        pk = pem.der_to_key(pk_bytes, 1)
        verification = partial(ecc.verif, level, pk_bytes, signature, vk)    #Verified
        encapsulation =  partial(ecc.encap, level, pk)
        c, _ = ecc.encap(level, pk)
        c_bytes = pem.serializeDer(c, 1)
        signing = partial(ecc.sign, level, c_bytes, sign_key)
        
    elif alg == "RSA":
        pk = pem.der_to_key(pk_bytes, 1)
        verification = partial(rsaalg.verif, level,pk_bytes,signature, vk)    #Verified
        encapsulation =  partial(rsaalg.encap, level, pk)
        c_bytes, _ = rsaalg.encap(level, pk)
        signing = partial(rsaalg.sign, level, c_bytes, sign_key)
    

    verification_time_s = timeit.repeat(verification , number=recurrence, repeat=repetition)
    encapsulation_time_s = timeit.repeat(encapsulation , number=recurrence, repeat=repetition)
    sign_time_s = timeit.repeat(signing , number=recurrence, repeat=repetition)
    #avg_time = (sum(verification_time) + sum(encapsulation_time)+ sum(sign_time))/repetition
    #return ((avg_time)/recurrence)*unit

    #Convert data from second to milisecond
    verification_time = [ x * 1000 for x in verification_time_s]
    encapsulation_time = [ x * 1000 for x in encapsulation_time_s]
    sign_time = [ x * 1000 for x in sign_time_s]

    #Counting Percentile
    result = {
        'Verification' : percentiles(verification_time),
        'Encapsulation' : percentiles(encapsulation_time),
        'Sign' : percentiles(sign_time)
    }
    
    return result



print("\nBENCHMARKING VERIFY, ENCAPSULATION, SIGN")
for alg in algorithms:
    for level in range(1,level_range):
        print(f'ALGORITMA {alg}  Level {level}')
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

        percentile = secondBench(alg, level, pk_bytes, sign_key, signature,vk, iteration)
        for key, value in percentile.items():
            print(key)
            for i, j in value.items():
                print(f"\t{i}: {j:}")

