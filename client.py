from sys import exception
from utils import ecc, kyber, pem, dilithium, rsaalg, files
from utils.percentiles import percentiles
import argparse
import requests
import random
import time

# Create the parser
parser = argparse.ArgumentParser(description="AKE Using ECDH and ECDSA")

# Add arguments
parser.add_argument('url', type=str, help='Define the api Url')
parser.add_argument('--verbose', action='store_true', help='Increase output verbosity')
parser.add_argument('-test', action='store_true', help="Running system test ")
parser.add_argument('-f', '--file',required=True , help="Specified the pubkey file, only support .pub extension")
parser.add_argument('-bench', action='store_true', help="Bench the protocol ")
args = parser.parse_args()

#main Function
def main(args,ssk, cl_vk_bytes, isPq):
    # Parse the arguments
    api_url = "http://127.0.0.1:8000/" if not args.url else args.url
    #Determine the algorithm and security level
    keysizes = {
        1312: 'dil1', 1952: 'dil2', 2592: 'dil3', 
        92 : 'ecdsa1',  124: 'ecdsa2', 158 : 'ecdsa3',
        422 : 'rsa1', 998 : 'rsa2', 1958 : 'rsa3',
    }
    

    #Determines Is it post quantum or not
    alg = keysizes[len(cl_vk_bytes)]
    level = 1 if "1" in alg else 2 if "2" in alg else 3
    isRsa = True if "rsa" in alg else False

    toMs = 1000000
    startMs = (time.process_time_ns()/toMs)
    # RUN KEYGEN AND WRITE TO FILE
    if isPq:
        #1. Generate Kyber Kem keypair
        sk, pk_bytes = kyber.keygen(level)
        #2.  Sign the Public Key
        signature = dilithium.sign(level, pk_bytes, ssk)
    else: 
        #1. Generate ECDH keypair, and change instance to Der
        sk, pk = ecc.keygen(level)
        pk_bytes = pem.serializeDer(pk, 1)
        #2.  Sign the Public Key
        signature = rsaalg.sign(level, pk_bytes, ssk) if isRsa else ecc.sign(level, pk_bytes, ssk)
    
    #In test mode generate random number for further verification
    idx = random.randint(round(len(signature)/3), round(len(signature)/2)) if args.test else 0
    totalMs = (time.process_time_ns()/toMs) - startMs
    startMs = (time.process_time_ns()/toMs)

    body={
        #Bytes need to transported as Hex to reduce size
        "isPq": isPq,
        "isRsa": isRsa,
        "isTest": idx,
        "kemPub": pk_bytes.hex(),
        "signature": signature.hex(),
        "vk": cl_vk_bytes.hex()[:10],
        "level": level
    }

    #3. Sending Requsest To server 
    try:
        response = requests.post(api_url + "/api/sessionGen", json=body,
            headers= {"Content-Type": "application/json"},
        )
    except exception as e:
        print(response.status_code)

    if response.status_code == 200:
        #4. Process Response from server
        sv_ciphertext = response.json().get("ciphertext")
        sv_signature = response.json().get("signature")
        c_bytes = bytes.fromhex(sv_ciphertext)
        signature_bytes = bytes.fromhex(sv_signature)

        #Open server public key
        if isPq:
            sv_vk = files.reads(True, True, 'keys/sv_vk')
            is_valid = dilithium.verif(level, c_bytes, signature_bytes, sv_vk)
            K = kyber.decap(level, sk, c_bytes) if is_valid else False
        else: 
            sv_vk = files.reads(False, True, 'keys/sv_vk')
            if isRsa:
                is_valid = rsaalg.verif(level, c_bytes, signature_bytes, sv_vk)
            else:
                is_valid = ecc.verif(level, c_bytes, signature_bytes, sv_vk)
            K = ecc.decap(level, sk, pem.der_to_key(c_bytes, 1)) if is_valid else False
                
        #Checking The whole process in test mod
        if args.test:
            alg = "Kyber_Dilithium" if isPq else "ECDH_RSA" if isRsa else "ECDH_ECDSA"
            try:
                assert bytes.fromhex(response.json().get("validator")) == pk_bytes[idx:idx*2] + signature[idx:idx*2] + signature_bytes[idx:idx*2] + c_bytes[idx:idx*2] + K 
                print(f"{alg} Level {level} Pass ✅")
                return(is_valid)
            except AssertionError as e:
                print(f"{alg} Level {level} Failed ❌")
                return(is_valid)
        else:
            print(totalMs + ((time.process_time_ns()/toMs) - startMs))
            return(is_valid)

    elif response.status_code == 400:
        print(response.content.decode())
    else: 
        print("Unknown Error, please try again")
        
if __name__ == "__main__":
    #load keypair
    try: 
        isPq = False
        ssk = files.reads(isPq, False, args.file)
        cl_vk = ssk.public_key()
        cl_vk_bytes = pem.serializeDer(cl_vk, 1)
    except Exception as e:
        try:
            isPq = True
            cl_vk_bytes = files.reads(True, True, args.file)
            ssk = files.reads(isPq, False, args.file)
        except Exception as e:
            print(f'Make Sure the file {args.file} exists')

    isValid = main(args, ssk, cl_vk_bytes, isPq)
    if isValid:
        print(f"Authenticated Key Exchange Success and Verified")
    else:
        print(f"Authenticated Key Exchange Failed")