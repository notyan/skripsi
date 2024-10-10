import subprocess
import os

def generate_rsa_keypair(key_size=2048):
    # Generate private key
    private_key_cmd = f"openssl ecparam -name secp256r1 -genkey -noout -out private_key.pem 2>/dev/null"
    subprocess.run(private_key_cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)



    # Extract public key
    # public_key_cmd = "openssl rsa -pubout -in private_key.pem -out public_key.pem"
    # subprocess.run(public_key_cmd, shell=True, check=True)

    # print(f"RSA key pair (size: {key_size} bits) generated successfully.")
    # print("Private key saved as 'private_key.pem'")
    # print("Public key saved as 'public_key.pem'")

# Generate the key pair
generate_rsa_keypair(3072)
