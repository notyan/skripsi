import argparse
from ast import arg
import timeit

from utils import dilithium, pem, rsaalg, ecc,kyber, files
from functools import partial  
import numpy as np

#In MS
unit = 1000000
iteration = 100
level_range = 1+3
algorithms =  ["PQ", "ECC", "RSA" ]
#algorithms =  ["ECC", "PQ"]

def percentiles(data: list):

    result = {
        'avg' : round(float(np.average(data)),4),
        'q50' : round(float(np.percentile(data, 50)),4),
        'q95' : round(float(np.percentile(data, 95)),4)
    }
    return result

def main():
    # Create the parser
    parser = argparse.ArgumentParser(description="A script to generate AKE Long-Term Secret using ECC")

    # Add arguments
    parser.add_argument('level', type=int, help='Security Level from 1-3')
    parser.add_argument('-pq' , action='store_true',  help="Use Post Quantum Cryptograpy")
    parser.add_argument('-b', '--bench',action='store_true', help="Run Benchmark")
    parser.add_argument('-o', '--output',required=False , help="Store the keypair into file")
    parser.add_argument('-rsa', action='store_true', help="Use RSA ")
    parser.add_argument('-test', action='store_true', help="Running system test ")
    parser.add_argument('--silent', action='store_true', help="Show no stdout on file writes")

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
    elif args.test:
        import os
        folder_path = "./tests"
        try:
            # List all files in the directory
            for filename in os.listdir(folder_path):
                file_path = os.path.join(folder_path, filename)
                
                # Check if it's a file (to avoid errors with directories)
                if os.path.isfile(file_path):
                    os.remove(file_path)  # Delete the file
        except Exception as e:
            print(f"An error occurred: {e}")

        for alg in algorithms:
            for level in range(1,4):
                if alg == "PQ":
                    ssk, vk = dilithium.keygen(level)
                    files.writes(True, False, ssk, folder_path + "/dilithium")
                    files.writes(True, True, vk, folder_path + "/dilithium")
                    ssk_load = files.reads(True, False, folder_path + "/dilithium")
                    vk_load = files.reads(True, True, folder_path + "/dilithium")
                    if ssk == ssk_load and vk == vk_load:
                        print(f'Dilithium Level {level} Keygen write & Load ... OK')
                elif alg == "ECC":
                    ssk, vk = ecc.keygen(level)
                    files.writes(False, False, ssk, folder_path + "/ECDSA")
                    files.writes(False, True, vk, folder_path + "/ECDSA")
                    ssk_load = files.reads(False, False, folder_path + "/ECDSA")
                    vk_load = files.reads(False, True, folder_path + "/ECDSA")
                    if pem.serialize(ssk,0) == pem.serialize(ssk_load,0) and pem.serialize(vk,1) == pem.serialize(vk_load,1):
                        print(f'ECDSA Level {level} Keygen write & Load ... OK')
                elif alg == "RSA":
                    ssk, vk = rsaalg.keygen(level)
                    files.writes(False, False, ssk, folder_path + "/RSA")
                    files.writes(False, True, vk, folder_path + "/RSA")
                    ssk_load = files.reads(False, False, folder_path + "/RSA")
                    vk_load = files.reads(False, True, folder_path + "/RSA")
                    if pem.serialize(ssk,0) == pem.serialize(ssk_load,0) and pem.serialize(vk,1) == pem.serialize(vk_load,1):
                        print(f'RSA Level {level} Keygen write & Load ... OK')

    else:
        # RUN KEYGEN AND WRITE TO FILE
        if args.pq:
            ssk, vk = dilithium.keygen(args.level)
            if args.output:
                files.writes(args.pq, False, ssk, args.output, args.silent)
                files.writes(args.pq, True, vk, args.output, args.silent)
            else:
                print(pem.sk_bytes_to_pem(ssk))
                print(pem.pk_bytes_to_pem(vk))
        else: 
            ssk, vk = rsaalg.keygen(args.level) if args.rsa else ecc.keygen(args.level)
            if args.output:
                files.writes(args.pq, False, ssk, args.output, args.silent)
                files.writes(args.pq, True, vk, args.output, args.silent)
            else:
                print(pem.serialize(ssk, 0).decode("utf-8"))
                print(pem.serialize(vk, 1).decode("utf-8"))

        
if __name__ == "__main__":
    main()
