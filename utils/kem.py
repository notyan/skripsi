from . import kyber, ecc
def keygen(level, isPq):
    if isPq:
        return kyber.keygen(level)
    else:
        return ecc.keygen(level)

def encap(level, isPq, public_key):
    if isPq:
        return kyber.encap(level, public_key)
    else:
        return ecc.encap(level, public_key)

def decap(level, isPq, secret_key, ciphertext):
    if isPq:
        return kyber.decap(level, secret_key, ciphertext)
    else:
        return ecc.decap(level, secret_key, ciphertext)
