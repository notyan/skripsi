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
    for level in range(level_range,0, -1):
        if alg == "PQ":
            sign_key, _ = dilithium.keygen(level)
        elif alg == "ECC":
            sign_key, _ = ecc.keygen(level)
        elif alg == "RSA":
            sign_key, _ = rsaalg.keygen(level)
        result = firstBench(alg, sign_key, level, iteration)
        #print(result)
        print(f'{alg} \t{level} \t{result["avg"]} \t\t{result["q50"]} \t\t{result["q95"]}')
           

