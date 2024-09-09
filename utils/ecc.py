from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

# Generate a private key using the SECP256R1 curve (one of the commonly used ECC curves)
def keygen(level):
    if level == 1:
        secret_key = ec.generate_private_key(ec.BrainpoolP256R1())
    elif level == 2:
        secret_key = ec.generate_private_key(ec.BrainpoolP384R1())
    elif level == 3:
        secret_key = ec.generate_private_key(ec.BrainpoolP512R1())
    public_key = secret_key.public_key()

    return secret_key, public_key

def sign(message, secret_key):
    signature = secret_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verif(message, signature, public_key):
    try:
        public_key.verify(
            signature, 
            message, 
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except:
        return False


def encap(user_secret_key, public_key):
    shared_key = user_secret_key.exchange(
    ec.ECDH(), public_key)
    
    return(shared_key)


# private_key = ec.generate_private_key(ec.SECP256R1())

# # Get the public key from the private key
# public_key = private_key.public_key()

# # Serialize the private key to PEM format for storage
# private_pem = private_key.private_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PrivateFormat.TraditionalOpenSSL,
#     encryption_algorithm=serialization.NoEncryption()  # No password for this example
# )

# # Serialize the public key to PEM format for storage
# public_pem = public_key.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo
# )

# # Print the PEM encoded keys
# print("Private Key:")
# print(private_pem.decode())

# print("\nPublic Key:")
# print(public_pem.decode())
