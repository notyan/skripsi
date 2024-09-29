from utils import kyber, pem, dilithium, rsaalg, ecc
import timeit
from functools import partial
import numpy as np


level_range = 3
iteration = 100
#algorithms =  ["RSA", "ECC", "PQ"]
algorithms =  ["ECC"]
#Timeit output are in second, multiply by 1000 to convert to ms
unit = 1000


def percentiles(data: list):

    result = {
        'avg' : round(float(np.average(data)),4),
        'q50' : round(float(np.percentile(data, 50)),4),
        'q95' : round(float(np.percentile(data, 95)),4)
    }
    return result


#Doing Keygeneration, and Signature
def firstBench(alg, sign_key, level, repetition):
    recurrence= int(repetition/10)
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

    keygen_time_s = timeit.repeat(keygeneration , number=recurrence, repeat=repetition)
    sign_time_s = timeit.repeat(signing , number=recurrence, repeat=repetition)

    #Convert data from second to milisecond
    keygen_time = [ (x * 1000)/recurrence for x in keygen_time_s]
    sign_time = [ (x * 1000)/recurrence for x in sign_time_s]
    running_time = [x + y for x,y in zip(keygen_time,sign_time)]

    return percentiles(running_time)

print("BENCHMARKING KEM KEYGEN AND SIGN")
print("Alg \tLevel \tAvg \t\tMedian \t\t95th")
for alg in algorithms:
    for level in range(1,level_range):
        if alg == "PQ":
            sign_key, _ = dilithium.keygen(level)
        elif alg == "ECC":
            sign_key, _ = ecc.keygen(level)
        elif alg == "RSA":
            sign_key, _ = rsaalg.keygen(level)
        result = firstBench(alg, sign_key, level, iteration)
        print(result)
        #print(f'{alg} \t{level} \t{result["avg"]} \t\t{result["q50"]} \t\t{result["q95"]}')
           


# def secondBench(alg, level, pk_bytes, sign_key, signature,vk, repetition):
#     recurrence= int(repetition/10)
#     if alg == "PQ":
#         verification = partial(dilithium.verif, level,pk_bytes,signature,vk)    #Verified
#         encapsulation =  partial(kyber.encap, level, pk_bytes)
#         c_bytes, _ = kyber.encap(level, pk_bytes)
#         signing = partial(dilithium.sign, level, c_bytes, sign_key)

#     elif alg == "ECC":
#         pk = pem.der_to_key(pk_bytes, 1)
#         verification = partial(ecc.verif, level, pk_bytes, signature, vk)    #Verified
#         encapsulation =  partial(ecc.encap, level, pk)
#         c, _ = ecc.encap(level, pk)
#         c_bytes = pem.serializeDer(c, 1)
#         signing = partial(ecc.sign, level, c_bytes, sign_key)
        
#     elif alg == "RSA":
#         pk = pem.der_to_key(pk_bytes, 1)
#         verification = partial(rsaalg.verif, level,pk_bytes,signature, vk)    #Verified
#         encapsulation =  partial(rsaalg.encap, level, pk)
#         c_bytes, _ = rsaalg.encap(level, pk)
#         signing = partial(rsaalg.sign, level, c_bytes, sign_key)
    

#     verification_time_s = timeit.repeat(verification , number=recurrence, repeat=repetition)
#     encapsulation_time_s = timeit.repeat(encapsulation , number=recurrence, repeat=repetition)
#     sign_time_s = timeit.repeat(signing , number=recurrence, repeat=repetition)
#     #avg_time = (sum(verification_time) + sum(encapsulation_time)+ sum(sign_time))/repetition
#     #return ((avg_time)/recurrence)*unit

#     #Convert data from second to milisecond
#     verification_time = [ x * 1000 for x in verification_time_s]
#     encapsulation_time = [ x * 1000 for x in encapsulation_time_s]
#     sign_time = [ x * 1000 for x in sign_time_s]

#     #Counting Percentile
#     result = {
#         'Verification' : percentiles(verification_time),
#         'Encapsulation' : percentiles(encapsulation_time),
#         'Sign' : percentiles(sign_time)
#     }
    
#     return result



# print("\nBENCHMARKING VERIFY, ENCAPSULATION, SIGN")
# for alg in algorithms:
#     for level in range(1,level_range):
#         print(f'ALGORITMA {alg}  Level {level}')
#         if alg == "PQ":
#             sign_key, vk = dilithium.keygen(level)
#             _, pk_bytes = kyber.keygen(level)
#             signature = dilithium.sign(level, pk_bytes, sign_key)
#         elif alg == "ECC":
#             _, pk = ecc.keygen(level)
#             pk_bytes = pem.serializeDer(pk, 1)
#             sign_key, vk = ecc.keygen(level)
#             signature = ecc.sign(level, pk_bytes, sign_key)
#         elif alg == "RSA":
#             _, pk = rsaalg.keygen(level)
#             pk_bytes = pem.serializeDer(pk, 1)
#             sign_key, vk = rsaalg.keygen(level)
#             signature = rsaalg.sign(level, pk_bytes, sign_key)

#         percentile = secondBench(alg, level, pk_bytes, sign_key, signature,vk, iteration)
#         for key, value in percentile.items():
#             print(key)
#             for i, j in value.items():
#                 print(f"\t{i}: {j:}")



# #Third bench already verified by testing each output to see if the verification and decapsulation give valid output
# def thirdBench(alg, level, sk_bytes: bytes, c_bytes: bytes, signature, vk,  repetition):
#     recurrence= int(repetition/10)
#     if alg == "PQ":
#         verification = partial(dilithium.verif, level, c_bytes, signature, vk)
#         decapsulation = partial(kyber.decap, level, sk_bytes, c_bytes)
#     elif alg == "ECC":
#         verification = partial(ecc.verif, level, c_bytes, signature, vk)
#         c = pem.der_to_key(c_bytes, 1)
#         sk = pem.der_to_key(sk_bytes, 0)
#         decapsulation = partial(ecc.decap, level, sk, c)
#     elif alg == "RSA":
#         verification = partial(rsaalg.verif, level, c_bytes, signature, vk)
#         sk = pem.der_to_key(sk_bytes, 0)
#         decapsulation = partial(rsaalg.decap, level, sk, c_bytes)

#     verification_time_s = timeit.repeat(verification , number=recurrence, repeat=repetition)
#     decapsulation_time_s = timeit.repeat(decapsulation , number=recurrence, repeat=repetition)

#     verification_time = [ x * 1000 for x in verification_time_s]
#     decapsulation_time = [ x * 1000 for x in decapsulation_time_s]
#     # avg_time = (sum(verification_time) + sum(decapsulation_time))/repetition
#     # return ((avg_time)/recurrence)*unit
    
#     #Counting Percentile
#     result = {
#         'Verification' : percentiles(verification_time),
#         'Decapsulation' : percentiles(decapsulation_time),
#     }
    
#     return result


# print("\nBENCHMARKING Verify and Decaps")
# for alg in algorithms:
#     for level in range(1,level_range):
#         print(f'ALGORITMA {alg}  Level {level}')
#         if alg == "PQ":
#             sign_key, vk = dilithium.keygen(level)
#             sk_bytes, pk_bytes = kyber.keygen(level)
#             c_bytes, K = kyber.encap(level, pk_bytes) 
#             signature = dilithium.sign(level, c_bytes, sign_key)
#         elif alg == "ECC":
#             sk, pk = ecc.keygen(level)
#             sign_key, vk = ecc.keygen(level)

#             sk_bytes = pem.serializeDer(sk, 0)
#             pk_bytes = pem.serializeDer(pk, 1)

#             #ECC c is a public key, and it will give instance type as outpus, so we need to convert 
#             c, K = ecc.encap(level, pk) 
#             c_bytes = pem.serializeDer(c, 1)
#             signature = ecc.sign(level, c_bytes, sign_key)

#         elif alg == "RSA":
#             sk, pk = rsaalg.keygen(level)
#             sign_key, vk = rsaalg.keygen(level)

#             sk_bytes = pem.serializeDer(sk, 0)
#             pk_bytes = pem.serializeDer(pk, 1)

#             c_bytes, K = rsaalg.encap(level, pk) 
#             signature = rsaalg.sign(level, c_bytes, sign_key)
#         percentile = thirdBench(alg, level, sk_bytes, c_bytes, signature, vk, iteration)
        
#         for key, value in percentile.items():
#             print(key)
#             for i, j in value.items():
#                 print(f"\t{i}: {j:}")