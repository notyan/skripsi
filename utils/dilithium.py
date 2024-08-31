import oqs

def keygen(level):
    #Select Security level for dilithium
    alg = "Dilithium2" if level == 1 else "Dilithium3" if level == 2 else "Dilithium5"
    
    #create the object
    signer = oqs.Signature(alg)
    #Generate keypair, and output the vk
    verification_key = signer.generate_keypair()
    #Extract the ssk from the object
    secret_key = signer.export_secret_key()
    return secret_key, verification_key

def sign(level, message, secret_key):
    alg = "Dilithium2" if level == 1 else "Dilithium3" if level == 2 else "Dilithium5"

    signer = oqs.Signature(alg, secret_key)
    signature = signer.sign(message)
    return signature

def verify(level, message, signature, verification_key):
    alg = "Dilithium2" if level == 1 else "Dilithium3" if level == 2 else "Dilithium5"

    verifier = oqs.Signature(alg)
    is_valid = verifier.verify(message, signature, verification_key)
    return is_valid