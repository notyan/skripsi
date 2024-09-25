from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import os



def keygen(level):
    alg = 3072 if level == 1 else 7680 if level == 2 else 15360

    secret_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=alg
    )
    
    public_key = secret_key.public_key()

    return secret_key, public_key

def sign(level, message, secret_key):
    signature = secret_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verif(level, message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

# Key Encapsulation
def encap(level, public_key):
    # Generate a random symmetric key (e.g., 256-bit key)
    shared_key = os.urandom(32) 
    # Encrypt the symmetric key using the RSA public key
    ciphertext = public_key.encrypt(
        shared_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext, shared_key  # Return both ciphertext and the symmetric key for demonstration

# Key Decapsulation
def decap(level, private_key, ciphertext):
    # Decrypt the ciphertext to retrieve the symmetric key
    shared_key = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return shared_key
