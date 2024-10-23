from sys import exception
from utils import ecc, kyber, pem, dilithium, rsaalg, files
import argparse
import requests
import random
import timeit

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
def main(args):
    # Parse the arguments
    api_url = "http://127.0.0.1:8000/" if not args.url else args.url
    #Determine the algorithm and security level
    keysizes = {
        1312: 'dil1', 1952: 'dil2', 2592: 'dil3', 
        92 : 'ecdsa1',  124: 'ecdsa2', 158 : 'ecdsa3',
        422 : 'rsa1', 998 : 'rsa2', 1958 : 'rsa3',
    }
    try:
        cl_vk_bytes = files.reads(True, True, args.file)
    except Exception as e:
        try:
            cl_vk = files.reads(False, True, args.file)
            cl_vk_bytes = pem.serializeDer(cl_vk, 1)
        except Exception as e:
            print(f'Make Sure the file {args.file} exists')
            return(e)
    alg = keysizes[len(cl_vk_bytes)]

    #Determines Is it post quantum or not
    isPq = False
    isRsa = False
    if "dil" in alg:
        isPq = True
    else:
        if "rsa" in alg:
            isRsa = True
    
    level = 1 if "1" in alg else 2 if "2" in alg else 3

    # RUN KEYGEN AND WRITE TO FILE
    if isPq:
        #1. Generate Kem keypair and write the SK into file
        sk, pk_bytes = kyber.keygen(level)
        #files.writes(isPq, False, sk, "keys/kyber")
        #2. Load the ssk then Sign the Public Key
        ssk = files.reads(isPq, False, args.file)
        signature = dilithium.sign(level, pk_bytes, ssk)
    else: 
        #1. Generate Kem keypair and write the SK into file
        sk, pk = ecc.keygen(level)
        pk_bytes = pem.serializeDer(pk, 1)
        #files.writes(isPq, False, sk, "keys/ecdh")

        #2.  Sign the Public Key
        if isRsa:
            ssk = files.reads(isPq, False, args.file)
            signature = rsaalg.sign(level, pk_bytes, ssk)
        else:
            ssk = files.reads(isPq, False, args.file)
            signature = ecc.sign(level, pk_bytes, ssk)
    
    if args.test:
        idx = random.randint(round(len(signature)/3), round(len(signature)/2))
    else: 
        idx = 0
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
        if isPq:
            #Open server public key
            sv_vk = files.reads(True, True, 'keys/sv_vk')
            is_valid = dilithium.verif(level, c_bytes, signature_bytes, sv_vk)
            if is_valid == True:
                K = kyber.decap(level, sk, c_bytes)
        else: 
            if isRsa:
                sv_vk = files.reads(False, True, 'keys/sv_vk')
                is_valid = rsaalg.verif(level, c_bytes, signature_bytes, sv_vk)
            else:
                sv_vk = files.reads(False, True, 'keys/sv_vk')
                is_valid = ecc.verif(level, c_bytes, signature_bytes, sv_vk)
            if is_valid == True:
                K = ecc.decap(level, sk, pem.der_to_key(c_bytes, 1))
                
        #Checking The whole process
        if args.test:
            alg = "Kyber_Dilithium" if isPq else "ECDH_RSA" if isRsa else "ECDH_ECDSA"
            try:
                assert bytes.fromhex(response.json().get("validator")) == pk_bytes[idx:idx*2] + signature[idx:idx*2] + signature_bytes[idx:idx*2] + c_bytes[idx:idx*2] + K 
                print(f"{alg} Level {level} Pass ✅")
            except AssertionError as e:
                print(f"{alg} Level {level} Failed ❌")
        else:
            return(is_valid)

    elif response.status_code == 400:
        print(response.content.decode())
    else: 
        print("Unknown Error, please try again")
        


if __name__ == "__main__":
    if args.bench:
        loops= 5
        from functools import partial
        process = partial(main,args)
        process_time_s = timeit.repeat(process, number=loops, repeat=100)    
        #Convert data from second to milisecond
        process_time = [ (x * 1000)/loops for x in process_time_s]
    else:
        if main(args):
            print(f"Authenticated Key Exchange Success and Verified")
        else:
            print(f"Authenticated Key Exchange Failed")
        
