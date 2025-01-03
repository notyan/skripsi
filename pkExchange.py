from math import e
from utils import ecc, kyber, pem, dilithium, rsaalg, files
import argparse
import requests
import random


#main Function
def main():
    # Create the parser
    parser = argparse.ArgumentParser(description="AKE Using ECDH and ECDSA")

    # Add arguments
    parser.add_argument('-f', '--file',required=True , help="Specified the pubkey file, only support .pub extension")
    parser.add_argument('url', type=str, help='Define the api Url')
    parser.add_argument('--silent', action='store_true', help="Show no stdout on file writes")

    # Parse the arguments
    args = parser.parse_args()
    api_url = "http://127.0.0.1:8000/" if not args.url else args.url
    #try to read the client Verification key and determines the algorithms
    try:
        vk = files.reads(True, True, args.file[:-4])
    except Exception as e:
        try:
            vk = files.reads(False, True, args.file[:-4])
        except Exception as e:
            print(f'Make Sure the file {args.file} exists')
            return(0)

    response = requests.post(
        api_url + "/api/vkExchange", 
        json= {"cl_vk": vk.hex()},
        headers= {"Content-Type": "application/json"},
    )

    vk_bytes = bytes.fromhex(response.json().get("sv_vk"))
    
    #write the server verification key and write to file
    try:
        files.writes(True, True, vk_bytes, "keys/sv_vk", args.silent)
    except Exception as e:
        try:
            files.writes(False, True, vk_bytes, "keys/sv_vk", args.silent)
        except Exception as e:
            print(e)

if __name__ == "__main__":
    main()
