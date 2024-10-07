from utils import ecc, kyber, pem, dilithium, rsaalg, files
import argparse
import requests

api_url = "http://127.0.0.1:8000/"
#main Function
def main():
    # Create the parser
    parser = argparse.ArgumentParser(description="AKE Using ECDH and ECDSA")

    # Add arguments
    parser.add_argument('level', type=int, help='Security Level from 1-3')
    parser.add_argument('-pq' , action='store_true',  help="AKE Using Kyber and Dilithium")
    parser.add_argument('-b', '--bench', action='store_true', help="Run Benchmark")
    parser.add_argument('-rsa', action='store_true', help="AKE Using ECDH and RSASign")
    parser.add_argument('--verbose', action='store_true', help='Increase output verbosity')

    # Parse the arguments
    args = parser.parse_args()

    # RUN KEYGEN AND WRITE TO FILE
    if args.pq:
        #1. Generate Kem keypair and write the SK into file
        sk, pk_bytes = kyber.keygen(args.level)
        files.writes(args.pq, False, sk, "keys/kyber")

        #2. Load the ssk then Sign the Public Key
        ssk = files.reads(args.pq, False, 'keys/dilithium')
        signature = dilithium.sign(args.level, pk_bytes, ssk)
    else: 
        #1. Generate Kem  keypair and write the secret Kem Keys into file
        sk, pk = ecc.keygen(args.level)
        pk_bytes = pem.serializeDer(pk, 1)
        files.writes(args.pq, False, sk, "keys/ecdh")

        #2.  Sign the Public Key
        ssk = files.reads(args.pq, False, 'keys/ecdsa')
        #Change public key pem to bytes that can be signed
        signature = ecc.sign(args.level, pk_bytes, ssk)
        print(pk_bytes)

    #3. Sending Requsest To server 
    response = requests.post(api_url + "/api/sessionGen", 
    #Bytes need to transported as Hex to reduce size
    json={
        "isPq": args.pq,
        "kemPub": pk_bytes.hex(),
        "signature": signature.hex(),
        "sigLevel": args.level,
        },
    headers={"Content-Type": "application/json"},
    )

    #4. Process Response from server
    sv_ciphertext = response.json().get("ciphertext")
    sv_signature = response.json().get("signature")
    if args.pq:
        #Open server public key
        sv_vk = files.reads(True, True, 'keys/sv_dilithium')
        is_valid = dilithium.verif(args.level, bytes.fromhex(sv_ciphertext), bytes.fromhex(sv_signature), sv_vk)
        print(is_valid)
    else: 
        sv_vk = files.reads(False, True, 'keys/sv_ecdsa')
        is_valid = ecc.verif(args.level, bytes.fromhex(sv_ciphertext), bytes.fromhex(sv_signature), sv_vk)
        print(is_valid)

    if is_valid == True:
        print("Handshake Verified")
    else: 
        print("Handshake invalid")

if __name__ == "__main__":
    main()
