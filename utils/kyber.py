import oqs
from utils import pem

def keygen(level):
    alg = "Kyber512" if level == 1 else "Kyber768" if level == 2 else "Kyber1024"
    party = oqs.KeyEncapsulation(alg)
    public_key = party.generate_keypair()
    secret_key = party.export_secret_key()

    #CHANGE to pem file
    return public_key, secret_key

def encap(level, public_key):
    alg = "Kyber512" if level == 1 else "Kyber768" if level == 2 else "Kyber1024"
    party = oqs.KeyEncapsulation(alg)
    ciphertext, shared_key = party.encap_secret(public_key)

    return ciphertext, shared_key

def decaps(level, secret_key, ciphertext):
    alg = "Kyber512" if level == 1 else "Kyber768" if level == 2 else "Kyber1024"
    party = oqs.KeyEncapsulation(alg, secret_key)
    shared_key = party.decap_secret(ciphertext)

    return(shared_key)