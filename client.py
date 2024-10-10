from utils import ecc, kyber, pem, dilithium, rsaalg, files
import argparse
import requests
import random

api_url = "http://127.0.0.1:8000/"

#main Function
def main():
    # Create the parser
    parser = argparse.ArgumentParser(description="AKE Using ECDH and ECDSA")

    # Add arguments
    parser.add_argument('level', type=int, help='Security Level from 1-3')
    parser.add_argument('-pq' , action='store_true',  help="AKE Using Kyber and Dilithium")
    parser.add_argument('-rsa', action='store_true', help="AKE Using ECDH and RSASign")
    parser.add_argument('--verbose', action='store_true', help='Increase output verbosity')
    parser.add_argument('-test', action='store_true', help="Running system test ")

    # Parse the arguments
    args = parser.parse_args()

    # RUN KEYGEN AND WRITE TO FILE
    if args.pq:
        #1. Generate Kem keypair and write the SK into file
        sk, pk_bytes = kyber.keygen(args.level)
        #files.writes(args.pq, False, sk, "keys/kyber")
        #2. Load the ssk then Sign the Public Key
        ssk = files.reads(args.pq, False, 'keys/cl_dilithium')
        signature = dilithium.sign(args.level, pk_bytes, ssk)
    else: 
        #1. Generate Kem keypair and write the SK into file
        sk, pk = ecc.keygen(args.level)
        pk_bytes = pem.serializeDer(pk, 1)
        #files.writes(args.pq, False, sk, "keys/ecdh")

        #2.  Sign the Public Key
        if args.rsa:
            ssk = files.reads(args.pq, False, 'keys/cl_rsa')
            signature = rsaalg.sign(args.level, pk_bytes, ssk)
        else:
            ssk = files.reads(args.pq, False, 'keys/cl_ecdsa')
            signature = ecc.sign(args.level, pk_bytes, ssk)
    
    if args.test:
        idx = random.randint(round(len(signature)/3), round(len(signature)/2))
    else: 
        idx = 0

    body={
        #Bytes need to transported as Hex to reduce size
        "isPq": args.pq,
        "isRsa": args.rsa,
        "isTest": idx,
        "kemPub": pk_bytes.hex(),
        "signature": signature.hex(),
        "level": args.level
    }
    
    #3. Sending Requsest To server 
    response = requests.post(api_url + "/api/sessionGen", json=body,
        headers= {"Content-Type": "application/json"},
    )

    #4. Process Response from server
    sv_ciphertext = response.json().get("ciphertext")
    sv_signature = response.json().get("signature")
    c_bytes = bytes.fromhex(sv_ciphertext)
    signature_bytes = bytes.fromhex(sv_signature)
    if args.pq:
        #Open server public key
        sv_vk = files.reads(True, True, 'keys/sv_dilithium')
        is_valid = dilithium.verif(args.level, c_bytes, signature_bytes, sv_vk)
        if is_valid == True:
            K = kyber.decap(args.level, sk, c_bytes)
    else: 
        if args.rsa:
            sv_vk = files.reads(False, True, 'keys/sv_rsa')
            is_valid = rsaalg.verif(args.level, c_bytes, signature_bytes, sv_vk)
        else:
            sv_vk = files.reads(False, True, 'keys/sv_ecdsa')
            is_valid = ecc.verif(args.level, c_bytes, signature_bytes, sv_vk)
        if is_valid == True:
            K = ecc.decap(args.level, sk, pem.der_to_key(c_bytes, 1))
            
    #Checking The whole process
    if args.test:
        alg = "Kyber_Dilithium" if args.pq else "ECDH_RSA" if args.rsa else "ECDH_ECDSA"
        try:
        # sv_validator = bytes.fromhex(response.json().get("validator"))
        # validator = pk_bytes[idx:idx*2] + signature[idx:idx*2] + signature_bytes[idx:idx*2] + c_bytes[idx:idx*2] + K
            assert bytes.fromhex(response.json().get("validator")) == pk_bytes[idx:idx*2] + signature[idx:idx*2] + signature_bytes[idx:idx*2] + c_bytes[idx:idx*2] + K 
            print(f"✅ {alg} Level {args.level} Passed Tests")
        except AssertionError as e:
            print(f"❌ {alg} Level {args.level} Failed Tests ")
        


if __name__ == "__main__":
    main()
