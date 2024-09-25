import base64
from cryptography.hazmat.primitives import serialization
##Should i remove the header?
def bytes_to_pem(key_bytes, key_type="PUBLIC KEY"):
    """Convert bytes to PEM format."""
    encoded = base64.b64encode(key_bytes).decode('utf-8')
    lines = [encoded[i:i+64] for i in range(0, len(encoded), 64)]
    pem = f"-----BEGIN {key_type}-----\n"
    pem += "\n".join(lines)
    pem += f"\n-----END {key_type}-----\n"
    return pem

def pem_to_bytes(pem_string):
    """Convert PEM format to bytes."""
    lines = pem_string.strip().split('\n')
    if lines[0].startswith('-----BEGIN') and lines[-1].startswith('-----END'):
        lines = lines[1:-1]
    der_base64 = ''.join(lines)
    der_bytes = base64.b64decode(der_base64)
    return der_bytes

def pk_bytes_to_pem(pk_bytes):
    """Convert public key bytes to PEM format."""
    return bytes_to_pem(pk_bytes, "PUBLIC KEY")

def sk_bytes_to_pem(sk_bytes):
    """Convert private key bytes to PEM format."""
    return bytes_to_pem(sk_bytes, "PRIVATE KEY")

def pk_pem_to_bytes(pk_pem):
    """Convert public key PEM to bytes."""
    return pem_to_bytes(pk_pem)

def sk_pem_to_bytes(sk_pem):
    """Convert private key PEM to bytes."""
    return pem_to_bytes(sk_pem)

#This will convert instance into PEM type
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

#This will convert instance into Bytes type
def serializeDer(key, type):
    if type == 0:
        return(key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    elif type == 1:
        return(key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    else:
        return("ERROR KEY OUTSIDE SCOPE")


def pem_to_key(key, type):
    if type == 0:
        return (serialization.load_pem_private_key(key, None))
    elif type == 1:
        return(serialization.load_pem_public_key(key, None))
    
    
def der_to_key(key, type):
    if type == 0:
        return (serialization.load_der_private_key(key, None))
    elif type == 1:
        return(serialization.load_der_public_key(key, None))