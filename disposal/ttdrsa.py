from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def generate_rsa_keypair(key_size=2048):
    """
    Generate an RSA keypair with the specified key size.
    
    :param key_size: Size of the key in bits (default: 2048)
    :return: A tuple containing (private_key, public_key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(message, private_key):
    """
    Sign a message using the provided private key.
    
    :param message: The message to sign (bytes)
    :param private_key: The RSA private key
    :return: The signature (bytes)
    """
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(message, signature, public_key):
    """
    Verify a signature using the provided public key.
    
    :param message: The original message (bytes)
    :param signature: The signature to verify (bytes)
    :param public_key: The RSA public key
    :return: True if the signature is valid, False otherwise
    """
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

# Example usage:
if __name__ == "__main__":
    # Key generation
    private_key, public_key = generate_rsa_keypair()
    
    # Message to sign
    message = b"Hello, World!"
    
    # Signing
    signature = sign_message(message, private_key)
    
    # Verification
    is_valid = verify_signature(message, signature, public_key)
    
    print(f"Message: {message.decode()}")
    print(f"Signature: {signature.hex()}")
    print(f"Signature valid: {is_valid}")
    
    # Example of invalid signature
    tampered_message = b"Hello, World? Tampered!"
    is_valid_tampered = verify_signature(tampered_message, signature, public_key)
    print(f"Tampered message: {tampered_message.decode()}")
    print(f"Signature valid for tampered message: {is_valid_tampered}")