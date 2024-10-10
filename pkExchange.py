from math import e
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
    parser.add_argument('-f', '--file',required=True , help="Specified the pubkey file, only support .pub extension")

    # Parse the arguments
    args = parser.parse_args()
    try:
        pk = files.reads(True, True, args.file[:-4])
    except Exception as e:
        try:
            pk = files.reads(False, True, args.file[:-4])
        except Exception as e:
            print(f'Make Sure the file {args.file} exists')
            return(0)

    #print(pk.hex())
    response = requests.post(
        api_url + "/api/pkExchange", 
        json= {"pk": pk.hex()},
        headers= {"Content-Type": "application/json"},
    )

    pk_bytes = bytes.fromhex(response.json().get("sv_pk"))
    
    try:
        files.writes(True, True, pk_bytes, "keys/sv_vk")
    except Exception as e:
        try:
            files.writes(False, True, pk_bytes, "keys/sv_vk")
        except Exception as e:
            print(e)

        


if __name__ == "__main__":
    main()
