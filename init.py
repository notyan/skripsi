from operator import truediv
from utils import kyber, pem, dilithium, rsaalg
import argparse
import requests


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
        isPq = True
        #1. Generate Kem keypair and write the SK into file
        sk, pk = kyber.keygen(args.level)
        f = open("keys/kyber", "w")
        f.write( pem.sk_bytes_to_pem(sk))
        f.close()

        #2. Load the ssk then Sign the Public Key
        ssk_pem = open('keys/dilithium', "r").read()
        ssk = pem.sk_pem_to_bytes(ssk_pem)
        signature = dilithium.sign(args.level, pk, ssk)

        """
        This Code Used to check if the key after conversion still have the same value
        f = open("keys/dilithium-check", "w")
        f.write( pem.sk_bytes_to_pem(ssk))
        f.close()
        """
    else: 
        isPq = False
        #1. Generate Kem  keypair
        sk, pk = rsaalg.keygen(args.level)
        #Write the secret Kem Keys into file
        f = open("keys/rsakem", "wb")
        f.write( pem.serialize(sk, 0))
        f.close()

        #Change public key pem to bytes that can be used
        pk = pem.serializeDer(pk, 1)

        #2.  Sign the Public Key
        ssk_pem =  open('keys/rsasig', "rb").read()
        ssk = pem.pem_to_key(ssk_pem, 0)
        signature = rsaalg.sign(pk, ssk)

    #3. Sending Requsest To server 
    print(signature)
    api_url = "http://127.0.0.1:8000/"
    response = requests.post(api_url + "/api/sessionGen", 
    json={
        #"ssk" :  ssk.hex(), 
        "isPq": isPq,
        "kemPub": pk.hex(),
        "signature": signature.hex(),
        "sigLevel": args.level,
        },
    headers={"Content-Type": "application/json"},
    )
    
    #print(response.json())

if __name__ == "__main__":
    main()
