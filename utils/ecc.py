from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

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

def encap(public_key, level):
    # Generate an ephemeral key pair
    if level == 1:
        ephemeral_private_key = ec.generate_private_key(ec.BrainpoolP256R1())
    elif level == 2:
        ephemeral_private_key = ec.generate_private_key(ec.BrainpoolP384R1())
    elif level == 3:
        ephemeral_private_key = ec.generate_private_key(ec.BrainpoolP512R1())
    ephemeral_public_key = ephemeral_private_key.public_key()
    
    # Perform key agreement
    shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)
    
    return ephemeral_public_key, shared_key

def decap(private_key, ephemeral_public_bytes):
    # Deserialize the ephemeral public key
    ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_bytes)
    
    # Perform key agreement
    shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)

    return shared_key
