from . import dilithium, ecc, rsaalg
def keygen(level, isPq, isRsa):
    if isPq:
        return dilithium.keygen(level)
    else:
        if isRsa:
            return rsaalg.keygen(level)
        else:
            return ecc.keygen(level)

def verif(level, isPq, isRsa, message, signature, public_key):
    if isPq:
        return dilithium.verif(level, message, signature, public_key)
    else:
        if isRsa:
            return rsaalg.verif(level, message, signature, public_key)
        else:
            return ecc.verif(level, message, signature, public_key)

def sign(level, isPq, isRsa, message, secret_key):
    if isPq:
        return dilithium.sign(level, message, secret_key)
    else:
        if isRsa:
            return rsaalg.sign(level, message, secret_key)
        else:
            return ecc.sign(level, message, secret_key)
