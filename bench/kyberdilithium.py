from operator import truediv
from ..utils import kyber, pem, dilithium, rsaalg
import requests
import time


iteration = 100
level_range = 4
for alg in ["KYBER", "DILITHIUM"]:
    for level in range(1,level_range):
        running_time= list()
        for i in range(iteration):
            if alg == "KYBER":
                start_time = time.time_ns()
                kyber.keygen(level)
                running_time.append(time.time_ns() - start_time)
            else:
                start_time = time.time_ns()
                dilithium.keygen(level)
                running_time.append(time.time_ns() - start_time)
        
        avg = (sum(running_time)/len(running_time))/1000000000
        print(f'Algoritma {alg} level {level} took { avg:.9f} s')