from utils import kyber, pem, dilithium, rsaalg, ecc
from utils.percentiles import percentiles
import timeit
from functools import partial
import numpy as np
import time


level_range = 4
iteration = 1000
#algorithms =  ["RSA", "ECC", "PQ"]
algorithms =  ["ECC", "PQ"]
#Timeit output are in second, multiply by 1000 to convert to ms
unit = 1000


#Doing Keygeneration, and Signature
def separate(sign_key, level, repetition):
    recurrence= int(repetition/10)
    keygeneration = partial(kyber.keygen, level)
    _, pk_bytes = kyber.keygen(level)
    signing = partial(dilithium.sign, level, pk_bytes, sign_key)

    keygen_time_s = timeit.repeat(keygeneration , number=recurrence, repeat=repetition)
    sign_time_s = timeit.repeat(signing , number=recurrence, repeat=repetition)

    #Convert data from second to milisecond
    keygen_time = [ (x * 1000)/recurrence for x in keygen_time_s]
    sign_time = [ (x * 1000)/recurrence for x in sign_time_s]
    running_time = [x + y for x,y in zip(keygen_time,sign_time)]
    #Counting Percentile
    
    result = percentiles(running_time)
    return result

def merge(sign_key, level, repetition):
    running_time = list()
    for i in range(0,repetition):
        start_time = time.time_ns()
        _, pk = kyber.keygen(level)
        dilithium.sign(level, pk, sign_key)
        running_time.append((time.time_ns() - start_time)/1000000)

    #Counting Percentile
    result = percentiles(running_time)
    return result

def separateTime(sign_key, level, repetition):
    running_time = list()
    for i in range(0,repetition):
        start_time = time.time_ns()
        _, pk = kyber.keygen(level)
        keygen_time = (time.time_ns() - start_time)
        start_time = time.time_ns()
        dilithium.sign(level, pk, sign_key)
        sign_time = (time.time_ns() - start_time)
        running_time.append((keygen_time + sign_time)/1000000)

    #Counting Percentile
    result = percentiles(running_time)
    return result

#level = 1
repetition = 10
# ssk, vk = dilithium.keygen(level)
# print(merge(ssk, level, 100))
# print(separateTime(ssk, level, 100))
# print(separate(ssk, level, 100))

def curve(level):
    keygeneration = partial(ecc.keygen, level)
    keygen_time = timeit.timeit(keygeneration , number=repetition)
    print((keygen_time/repetition)*1000)

curve(1)
curve(2)
curve(3)

