from operator import truediv
from utils import kyber, pem, dilithium, rsaalg, ecc
import time
import timeit

level = 1
repetition = 100
iteration = 10

ecdsa_ssk, ecdsa_vk = ecc.keygen(level)
_, pk = ecc.keygen(level)
print((timeit.timeit(lambda: pem.serialize(pk, 1) , number=repetition)*10))

start_time = time.time_ns()
pem.serialize(pk, 1)
print((time.time_ns() - start_time)/1000000)

# start_time = time.time_ns()
# results = timeit.repeat(lambda: kyber.keygen(1), repeat=repetition, number=iteration)
# results_in_milliseconds = [time * 1000 for time in results]
# print(len(results_in_milliseconds))
# print(time.time_ns() - start_time)

# append_result = list()
# start_time = time.time_ns()
# for i in range(0, repetition):
#     append_result.append(timeit.timeit(lambda: kyber.keygen(1), number=iteration))

# print(len(append_result))
# print(time.time_ns() - start_time)