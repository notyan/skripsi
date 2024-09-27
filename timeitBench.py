from fastapi.background import P
from utils import kyber, pem, dilithium, rsaalg, ecc
import timeit
from functools import partial


level_range = 4
iteration = 100
algorithms =  ["RSA", "ECC", "PQ"]
#algorithms =  ["PQ"]
#Timeit output are in second, multiply by 1000 to convert to ms
unit = 1000

#Doing Keygeneration, and Signature
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
    return ((keygen_time + sign_time)/iteration)*unit


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
    

    verification_time = timeit.timeit(verification , number=repetition)
    encapsulation_time = timeit.timeit(encapsulation , number=repetition)
    sign_time = timeit.timeit(signing , number=repetition)
    return ((verification_time + encapsulation_time + sign_time)/iteration)*unit



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



#Third bench already verified by testing each output to see if the verification and decapsulation give valid output
def thirdBench(alg, level, sk_bytes: bytes, c_bytes: bytes, signature, vk,  repetition):
    if alg == "PQ":
        verification = partial(dilithium.verif, level, c_bytes, signature, vk)
        decapsulation = partial(kyber.decap, level, sk_bytes, c_bytes)
    elif alg == "ECC":
        verification = partial(ecc.verif, level, c_bytes, signature, vk)
        c = pem.der_to_key(c_bytes, 1)
        sk = pem.der_to_key(sk_bytes, 0)
        decapsulation = partial(ecc.decap, level, sk, c)
    elif alg == "RSA":
        verification = partial(rsaalg.verif, level, c_bytes, signature, vk)
        sk = pem.der_to_key(sk_bytes, 0)
        decapsulation = partial(rsaalg.decap, level, sk, c_bytes)

    verification_time = timeit.timeit(verification , number=repetition)
    decapsulation_time = timeit.timeit(decapsulation , number=repetition)
    return ((verification_time + decapsulation_time)/iteration)*unit


print("\nBENCHMARKING Verify and Decaps")
for alg in algorithms:
    print(f'ALGORITMA {alg} \nLevel\tTime')
    for level in range(1,level_range):
        if alg == "PQ":
            sign_key, vk = dilithium.keygen(level)
            sk_bytes, pk_bytes = kyber.keygen(level)
            c_bytes, K = kyber.encap(level, pk_bytes) 
            signature = dilithium.sign(level, c_bytes, sign_key)
        elif alg == "ECC":
            sk, pk = ecc.keygen(level)
            sign_key, vk = ecc.keygen(level)

            sk_bytes = pem.serializeDer(sk, 0)
            pk_bytes = pem.serializeDer(pk, 1)

            #ECC c is a public key, and it will give instance type as outpus, so we need to convert 
            c, K = ecc.encap(level, pk) 
            c_bytes = pem.serializeDer(c, 1)
            signature = ecc.sign(level, c_bytes, sign_key)

        elif alg == "RSA":
            sk, pk = rsaalg.keygen(level)
            sign_key, vk = rsaalg.keygen(level)

            sk_bytes = pem.serializeDer(sk, 0)
            pk_bytes = pem.serializeDer(pk, 1)

            c_bytes, K = rsaalg.encap(level, pk) 
            signature = rsaalg.sign(level, c_bytes, sign_key)
        print(thirdBench(alg, level, sk_bytes, c_bytes, signature, vk, iteration))