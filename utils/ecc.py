from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

# Generate a private key using the SECP256R1 curve (one of the commonly used ECC curves)
def keygen(level):
    secret_key = ec.generate_private_key(ec.BrainpoolP256R1()) if level == 1 else ec.generate_private_key(ec.BrainpoolP384R1()) if level == 2 else ec.generate_private_key(ec.BrainpoolP512R1())

    return secret_key, secret_key.public_key()


def sign(level, message, secret_key):
    signature = secret_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verif(level, message, signature: bytes, public_key):
    try:
        public_key.verify(
            signature, 
            message, 
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except:
        return False

def encap(level, public_key):
    # Generate an ephemeral key pair
    ephemeral_private_key = ec.generate_private_key(ec.BrainpoolP256R1()) if level == 1 else ec.generate_private_key(ec.BrainpoolP384R1()) if level == 2 else ec.generate_private_key(ec.BrainpoolP512R1())

    #Return public key and key agreement shared key
    return ephemeral_private_key.public_key() ,  ephemeral_private_key.exchange(ec.ECDH(), public_key)

def decap(level, private_key, ephemeral_public_key):
    # # Deserialize the ephemeral public key
    # ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_bytes)
    
    # Perform key agreement
    return private_key.exchange(ec.ECDH(), ephemeral_public_key)
