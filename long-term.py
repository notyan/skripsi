import argparse
import time
import timeit
from utils import dilithium, pem, rsaalg, ecc  

def main():
    # Create the parser
    parser = argparse.ArgumentParser(description="A script to generate AKE Long-Term Secret")

    # Add arguments
    parser.add_argument('level', type=int, help='Security Level from 1-3')
    parser.add_argument('-pq' , action='store_true',  help="Use Post Quantum Cryptograpy")
    parser.add_argument('-b', '--bench',action='store_true', help="Run Benchmark")
    parser.add_argument('--verbose', action='store_true', help='Increase output verbosity')

    # Parse the arguments
    args = parser.parse_args()
    if args.bench:
        for alg in ["ECC", "DILITHIUM"]:
            for level in range(1,4):
                running_time= list()
                for i in range(50):
                    if alg == "RSA":
                        start_time = time.time_ns()
                        rsaalg.keygen(level)
                        running_time.append(time.time_ns() - start_time)
                    elif alg == "ECC":
                        start_time = time.time_ns()
                        ecc.keygen(level)
                        running_time.append(time.time_ns() - start_time)
                    else:
                        start_time = time.time_ns()
                        dilithium.keygen(level)
                        running_time.append(time.time_ns() - start_time)
                
                avg = (sum(running_time)/len(running_time))/1000000000
                print(f'Algoritma {alg} level {level} took { avg:.9f} s')
            

    else:
        # RUN KEYGEN AND WRITE TO FILE
        if args.pq:
            ssk, vk = dilithium.keygen(args.level)
        
            f = open("keys/dilithium", "w")
            #CONVERT TO PEM, than write to file
            f.write( pem.sk_bytes_to_pem(ssk))
            f.close()
            f = open("keys/dilithium.pub", "w")
            #CONVERT TO PEM, than write to file
            f.write(pem.pk_bytes_to_pem(vk))
            f.close()
        else: 
            ssk, vk = rsaalg.keygen(args.level)
            f = open("keys/ecdsa", "wb")
            f.write(pem.serialize(ssk, 0 ))
            f.close()

            f = open("keys/ecdsa.pub", "wb")
            f.write(pem.serialize(vk, 1))
            f.close()
        
if __name__ == "__main__":
    main()
