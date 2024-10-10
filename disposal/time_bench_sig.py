import oqs
import time
from pprint import pprint
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def dilithium_keygen(level):
    alg = "Dilithium2"
    #Select Security level for dilithium
    alg = "Dilithium2" if level == 1 else "Dilithium3" if level == 2 else "Dilithium5"
    
    #create the object
    signer = oqs.Signature(alg)
    #Generate keypair, and output the vk
    public_key = signer.generate_keypair()
    #Extract the ssk from the object
    secret_key = signer.export_secret_key()
    return secret_key, public_key

def dilithium_sign(message, secret_key, sec):
    signer = oqs.Signature(sec, secret_key)
    signature = signer.sign(message)
    return signature

def dilithium_verify(message, signature, public_key, sec):
    verifier = oqs.Signature(sec)
    is_valid = verifier.verify(message, signature, public_key)
    return is_valid

def rsa_keygen(level):
    alg = 3072 if level == 1 else 7680 if level == 2 else 15360

    secret_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=alg
    )
    public_key = secret_key.public_key()

    return secret_key, public_key

def rsa_sign(message, secret_key):
    signature = secret_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def rsa_verify(message, signature, public_key):
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

def keygen(alg, level):
    if alg  == "RSA":
        ssk, vk  = rsa_keygen(level)
        return ssk,vk
    else:
        ssk, vk = dilithium_keygen(level)
        return ssk,vk

def sign(alg, message, secret_key,level):
    if alg == "RSA":
        return(rsa_sign(message, secret_key))
    elif alg == "Dilithium":
        sec = "Dilithium2" if level == 1 else "Dilithium3" if level == 2 else "Dilithium5" if level ==3 else "ERROR"
        return(dilithium_sign(message, secret_key, sec))
    else:
        print("Algorithm outside the scope")

def verify(alg, message, signature, public_key, level):
    if alg == "RSA":
        return(rsa_verify(message, signature, public_key))
    elif alg == "Dilithium":
        sec = "Dilithium2" if level == 1 else "Dilithium3" if level == 2 else "Dilithium5" if level ==3 else "ERROR"
        return(dilithium_verify(message, signature, public_key, sec))
    else:
        print("Algorithm outside the scope")


#Sign process
#algorithm = ["Dilithium", "RSA"]
#for alg in algorithm:
alg = "Dilithium"
for level in range(1,0,-1):
    print (alg, level)
    kyg =0
    sig =0
    ver =0 
    iteration=100
    for i in range(0,iteration):
        msg= b"Niggero"

        start_time = time.time()
        ssk,vk = keygen(alg,level)
        kyg+= time.time() - start_time

        start_time = time.time()
        signature = sign(alg,msg, ssk, level)
        sig+= time.time() - start_time

        start_time = time.time()
        is_valid = verify(alg, msg, signature, vk, level) 
        ver+= time.time() - start_time
    
    print("Average Running time %s, %s, %s" % (kyg/iteration, sig/iteration, ver/iteration))  
    kyg =0
    sig =0
    ver =0 
    
# ssk,vk = keygen(alg,1)
# msg= b"Niggero"
# signature = sign(alg,msg, ssk, 1)
# is_valid = verify(alg, msg, signature, vk, 1) 

# print(f"Message: {msg.decode()}")
# print(f"Signature: {signature.hex()}")
# print(f"Signature valid: {is_valid}")

# #Fake msg
# fakemsg = b"nega"
# is_valid = verify(alg, fakemsg, signature, vk, 1) 
# print(f"Tampered msg verified: {is_valid}")

# #Fake VK
# tssk,tvk = keygen(alg,1)
# is_valid = verify(alg, msg, signature, tvk, 1) 
# print(f"Tampered vk verified: {is_valid}")





