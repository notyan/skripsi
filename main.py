from signal import pthread_kill
from sys import exception
from typing import Union
from utils import files, kyber, pem, dilithium, ecc, rsaalg
from pydantic import BaseModel
from fastapi import FastAPI

app = FastAPI()

def find_key(dictionary, value):
    return next((key for key, value in dictionary.items() if value == value), None)

class Protocol(BaseModel):
    isPq: bool
    isTest: int
    isRsa: bool
    kemPub: str
    signature: str
    level: int

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.post("/api/sessionGen")
async def start(keys: Protocol):
    #1. Verify PK KEM
    if keys.isPq :
        #open Client Public Keys
        cl_vk = files.reads(keys.isPq, True, 'keys/cl_dilithium')
        #kempub and signature are sent by hex, so we need to convert it back to bytes
        is_valid = dilithium.verif(keys.level, bytes.fromhex(keys.kemPub), bytes.fromhex(keys.signature), cl_vk)
    else :
        if keys.isRsa:
            cl_vk = files.reads(keys.isPq, True, 'keys/cl_rsa')
            #kempub and signature are sent by hex, so we need to convert it back to bytes
            is_valid = rsaalg.verif(keys.level, bytes.fromhex(keys.kemPub), bytes.fromhex(keys.signature), cl_vk)
        else:
            cl_vk = files.reads(keys.isPq, True, 'keys/cl_ecdsa')
            #kempub and signature are sent by hex, so we need to convert it back to bytes
            is_valid = ecc.verif(keys.level, bytes.fromhex(keys.kemPub), bytes.fromhex(keys.signature), cl_vk)

    #2. Generate and Encapsulate K, then sign
    if is_valid :
        if keys.isPq :
            #K Generation and encapsulation
            c_bytes, K = kyber.encap(keys.level, bytes.fromhex(keys.kemPub))
            #Ciphertext Signing Process
            sv_ssk = files.reads(keys.isPq, False, 'keys/sv_dilithium') 
            signature = dilithium.sign(keys.level, c_bytes, sv_ssk)
        else:
            kemPublic_bytes = bytes.fromhex(keys.kemPub) 
            kemPublic = pem.der_to_key(kemPublic_bytes,1)
            c, K = ecc.encap(keys.level, kemPublic)
            c_bytes = pem.serializeDer(c, 1)

            #Open the server signature key, and change from pem  to instance
            if keys.isRsa:
                sv_ssk = files.reads(keys.isPq, False, 'keys/sv_rsa') 
                signature = rsaalg.sign(keys.level, c_bytes, sv_ssk)
            else:
                sv_ssk = files.reads(keys.isPq, False, 'keys/sv_ecdsa') 
                signature = ecc.sign(keys.level, c_bytes, sv_ssk)
        #Sent The signature alongside the ciphertext

        if keys.isTest != 0:
            n = keys.isTest
            return{"validator" : (bytes.fromhex(keys.kemPub)[n:n*2] + 
                   bytes.fromhex(keys.signature)[n:n*2] +
                   signature[n:n*2] + c_bytes[n:n*2] + K ).hex(), 
                   "signature" : signature.hex(), 
                   "ciphertext" : c_bytes.hex()
                   }
        else: 
            return{"signature" : signature.hex(), "ciphertext" : c_bytes.hex()}
    
    else: 
        print("Verification Invalid Maybe Somebody change the data")




@app.post("/api/testSession")
async def testing(keys: Protocol):
    if keys.isPq :
        #open Client Public Keys
        cl_vk = files.reads(keys.isPq, True, 'keys/cl_vk')
        is_valid = dilithium.verif(keys.level, bytes.fromhex(keys.kemPub), bytes.fromhex(keys.signature), cl_vk)
    else :
        if keys.isRsa:
            cl_vk = files.reads(keys.isPq, True, 'keys/cl_vk')
            is_valid = rsaalg.verif(keys.level, bytes.fromhex(keys.kemPub), bytes.fromhex(keys.signature), cl_vk)
        else:
            cl_vk = files.reads(keys.isPq, True, 'keys/cl_vk')
            is_valid = ecc.verif(keys.level, bytes.fromhex(keys.kemPub), bytes.fromhex(keys.signature), cl_vk)

    if is_valid :
        if keys.isPq :
            c_bytes, K = kyber.encap(keys.level, bytes.fromhex(keys.kemPub))
            sv_ssk = files.reads(keys.isPq, False, 'keys/sv_dilithium') 
            signature = dilithium.sign(keys.level, c_bytes, sv_ssk)
        else:
            kemPublic_bytes = bytes.fromhex(keys.kemPub) 
            #TODO change this block for better process 
            #print(kemPublic_bytes.encode())  
            #kemPublic = pem.serializeDer(kemPublic_bytes.encode(), 1)
            kemPublic_pem = pem.pk_bytes_to_pem(kemPublic_bytes)        #Change bytes to pem
            kemPublic = pem.pem_to_key(kemPublic_pem.encode(), 1)       #Encode pem -> bytes -> instance
            c, K = ecc.encap(keys.level, kemPublic)
            #Open the server signature key, and change from pem  to instance
            sv_ssk = files.reads(keys.isPq, False, 'keys/sv_ecdsa') 
            #Ciphertext Signing Process for ECC Only:
            c_bytes = pem.serializeDer(c, 1)
            signature = ecc.sign(keys.level, c_bytes, sv_ssk)
            #Ciphertext Signing Process for RSA Only:
            #signature = rsaalg.sign(keys.level, c, sv_ssk)
    else: 
        print("Verification Invalid")

    #Sent The signature alongside the ciphertext
    return{"signature" : signature.hex(), "ciphertext" : c_bytes.hex()}


@app.get("/api/sig_gen")
def read_item(item_id: int, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}

class PublicKey(BaseModel):
    pk: str


@app.post("/api/pkExchange")
async def pkExchange(keys: PublicKey):
    keysizes = {
        'dil1': 1312, 'dil2': 1952, 'dil3': 2592,
        'ecdsa1': 92, 'ecdsa2': 124, 'ecdsa3': 158,
        'rsa1': 422, 'rsa2': 998, 'rsa3': 1958,
    }
    pq = [1312, 1952, 2592]
    keysize = len(bytes.fromhex(keys.pk))
    result = find_key(keysizes, keysize)
    if "dil" in result:
        pk = files.reads(True, True, "../keys/" + result)
    else:
        pk = files.reads(True, True, "../keys/" + result)
    print(result)
    print(pk[:20])
    return {"sv_pk" : pk.hex()}

@app.post("/api/sessionStart")
async def init(keys: Protocol):
    ciphertext = kyber.encap(keys.kemalg, keys.pubkey) 
    return {"ciphertext": ciphertext}