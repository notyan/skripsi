import argparse
from utils import kyber, pem, rsaalg

def main():
    # Create the parser
    parser = argparse.ArgumentParser(description="A simple script to demonstrate argparse.")

    # Add arguments
    parser.add_argument('level', type=int, help='Security Level from 1-3')
    parser.add_argument('-pq' , action='store_true',  help="Use Post Quantum Cryptograpy")
    parser.add_argument('--verbose', action='store_true', help='Increase output verbosity')

    # Parse the arguments
    args = parser.parse_args()

    # RUN KEYGEN AND WRITE TO FILE
    if args.pq:
        sk, pk = kyber.keygen(args.level)
        f = open("kyber", "w")
        f.write(sk)
        f.close()
        f = open("kyber.pub", "w")
        f.write(pk)
        f.close()
    else: 
        sk, pk = rsaalg.keygen(args.level)
        f = open("rsa", "wb")
        f.write(sk)
        f.close()

        f = open("rsa.pub", "wb")
        f.write(pk)
        f.close()
        

if __name__ == "__main__":
    main()
