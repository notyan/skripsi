from utils import kyber, pem, dilithium, rsaalg
import argparse
'''
TODO
1. kem.keygen
2. sign.kem.pubkey
3. request to server and sent pk , signature, algorithm used
'''

#main Function
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
        #1. Generate Kem keypair
        sk, pk = kyber.keygen(args.level)
        ssk_pem = open('keys/dilithium', "r").read()
        ssk = pem.sk_pem_to_bytes(ssk_pem)

        """
        This Code Used to check if the key after conversion still have the same value
        f = open("keys/dilithium-check", "w")
        f.write( pem.sk_bytes_to_pem(ssk))
        f.close()
        """
        #signature = dilithium.sign(args.level , pk, ssk)
    else: 
        #1. Generate Kem  keypair
        sk, pk = rsaalg.keygen(args.level)
        ssk_pem =  open('keys/rsasig', "rb").read()
        #print(ssk_pem)
        ssk = pem.pem_to_key(ssk_pem, 0)

        f = open("keys/rsa-check", "wb")
        f.write( pem.serialize(ssk, 0))
        f.close()
    


if __name__ == "__main__":
    main()
