import argparse
from utils import dilithium, pem, rsaalg

def main():
    # Create the parser
    parser = argparse.ArgumentParser(description="A script to generate AKE Long-Term Secret")

    # Add arguments
    parser.add_argument('level', type=int, help='Security Level from 1-3')
    parser.add_argument('-pq' , action='store_true',  help="Use Post Quantum Cryptograpy")
    parser.add_argument('--verbose', action='store_true', help='Increase output verbosity')

    # Parse the arguments
    args = parser.parse_args()

    # RUN KEYGEN AND WRITE TO FILE
    if args.pq:
        sk, pk = dilithium.keygen(args.level)
    
        f = open("keys/dilithium", "w")
        #CONVERT TO PEM, than write to file
        f.write( pem.sk_bytes_to_pem(sk))
        f.close()
        f = open("keys/dilithium.pub", "w")
        #CONVERT TO PEM, than write to file
        f.write(pem.pk_bytes_to_pem(pk))
        f.close()
    else: 
        sk, pk = rsaalg.keygen(args.level)
        f = open("keys/rsasig", "wb")
        f.write(pem.serialize(sk, 0 ))
        f.close()

        f = open("keys/rsasig.pub", "wb")
        f.write(pem.serialize(pk, 1))
        f.close()
        

if __name__ == "__main__":
    main()
