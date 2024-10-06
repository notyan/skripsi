import argparse
from ast import arg
import timeit
from utils import dilithium, pem, rsaalg, ecc,kyber
from functools import partial  
import numpy as np

#In MS
unit = 1000000
iteration = 100
level_range = 1+3
algorithms =  ["RSA", "ECC", "PQ"]
#algorithms =  ["RSA", "PQ"]

def percentiles(data: list):

    result = {
        'avg' : round(float(np.average(data)),4),
        'q50' : round(float(np.percentile(data, 50)),4),
        'q95' : round(float(np.percentile(data, 95)),4)
    }
    return result

def writeToFile(pq, isPub, key, path):
    
    if isPub:
        f = open(path + ".pub", "w")
        if pq:
            f.write(pem.pk_bytes_to_pem(key))
        else:
            f.write(pem.serialize(key, 1).decode("utf-8"))
        f.close()
        print("Public Key Written into " + path + ".pub")
    else:
        f = open(path, "w")
        if pq:
            f.write(pem.sk_bytes_to_pem(key))
        else:
            f.write(pem.serialize(key, 0).decode("utf-8"))  
        f.close()
        print("Private Key Written into " + path)

            


def main():
    # Create the parser
    parser = argparse.ArgumentParser(description="A script to generate AKE Long-Term Secret")

    # Add arguments
    parser.add_argument('level', type=int, help='Security Level from 1-3')
    parser.add_argument('-pq' , action='store_true',  help="Use Post Quantum Cryptograpy")
    parser.add_argument('-b', '--bench',action='store_true', help="Run Benchmark")
    parser.add_argument('-o', '--output',required=False , help="Store the keypair into file")
    parser.add_argument('--verbose', action='store_true', help='Increase output verbosity')

    # Parse the arguments
    args = parser.parse_args()
    if args.bench:
        print("Bench ,Alg ,Level ,Avg ,Median ,95th")
        recurrence= int(iteration/10)
        for level in range(1,level_range):
            kyber_keygen = partial(kyber.keygen, level)
            kyber_time_s = timeit.repeat(kyber_keygen , number=recurrence, repeat=iteration)
            kyber_time = [ (x * 1000)/recurrence for x in kyber_time_s]
            kyber_res = percentiles(kyber_time)
            print(f'Keygen, Kyber, {level}, {kyber_res["avg"]}, {kyber_res["q50"]}, {kyber_res["q95"]}')
        
        for level in range(1,level_range):
            dilithium_keygen = partial(dilithium.keygen, level)
            dilithium_time_s = timeit.repeat(dilithium_keygen , number=recurrence, repeat=iteration)
            dilithium_time = [ (x * 1000)/recurrence for x in dilithium_time_s]
            dilithium_res = percentiles(dilithium_time)
            print(f'Keygen, Dilithium, {level}, {dilithium_res["avg"]}, {dilithium_res["q50"]}, {dilithium_res["q95"]}')

        for level in range(1,level_range):
            ecc_keygen = partial(ecc.keygen, level)
            ecc_time_s = timeit.repeat(ecc_keygen , number=recurrence, repeat=iteration)
            ecc_time = [ (x * 1000)/recurrence for x in ecc_time_s]
            ecc_res = percentiles(ecc_time)
            print(f'Keygen, ECC, {level}, {ecc_res["avg"]}, {ecc_res["q50"]}, {ecc_res["q95"]}')

        for level in range(1, level_range):
            rsaalg_keygen = partial(rsaalg.keygen, level)
            rsaalg_time_s = timeit.repeat(rsaalg_keygen , number=recurrence, repeat=iteration)
            rsaalg_time = [ (x * 1000)/recurrence for x in rsaalg_time_s]
            rsaalg_res = percentiles(rsaalg_time)
            print(f'Keygen, RSA, {level}, {rsaalg_res["avg"]}, {rsaalg_res["q50"]}, {rsaalg_res["q95"]}')



    else:
        # RUN KEYGEN AND WRITE TO FILE
        if args.pq:
            ssk, vk = dilithium.keygen(args.level)
            if args.output:
                writeToFile(True, False, ssk, args.output)
                writeToFile(True, True, vk, args.output)
            else:
                print(pem.sk_bytes_to_pem(ssk))
                print(pem.pk_bytes_to_pem(vk))
        else: 
            ssk, vk = ecc.keygen(args.level)
            if args.output:
                writeToFile(False, False, ssk, args.output)
                writeToFile(False, True, vk, args.output)
            else:
                print(pem.serialize(ssk, 0).decode("utf-8"))
                print(pem.serialize(vk, 1).decode("utf-8"))

        
if __name__ == "__main__":
    main()
