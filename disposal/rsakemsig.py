from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


def keygen(level):
    alg = 3072 if level == 1 else 7680 if level == 2 else 15360

    secret_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=alg
    )
    public_key = secret_key.public_key()

    return secret_key, public_key

def sign(message, secret_key):
    signature = secret_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify(message, signature, public_key):
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
    
def serialize(key, type):
    #type 0 = private , type 1 = public
    if type == 0:
        return(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    elif type == 1:
        return(key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    else:
        return("ERROR KEY OUTSIDE SCOPE")