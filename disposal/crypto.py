from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def generate_keypair():
    # Generate a new RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(message, private_key):
    # Sign the message
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(message, signature, public_key):
    # Verify the signature
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# Example usage
if __name__ == "__main__":
    # Generate a new key pair
    private_key, public_key = generate_keypair()
    
    # Message to be signed
    message = "Hello, World!"
    
    # Sign the message
    signature = sign_message(message, private_key)
    print(f"Signature: {signature.hex()}")
    
    # Verify the signature
    is_valid = verify_signature(message, signature, public_key)
    print(f"Signature is valid: {is_valid}")
    
    # Try to verify with a tampered message
    tampered_message = "Hello, World? "
    is_tampered_valid = verify_signature(tampered_message, signature, public_key)
    print(f"Tampered signature is valid: {is_tampered_valid}")