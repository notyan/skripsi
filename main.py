from typing import Union
from utils import files, kyber, pem, dilithium, ecc, rsaalg
from pydantic import BaseModel
from fastapi import FastAPI

app = FastAPI()

class Protocol(BaseModel):
    isPq: bool
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

    else: 
        print("Verification Invalid")

    # #Sent The signature alongside the ciphertext
    return{"signature" : signature.hex(), "ciphertext" : c_bytes.hex()}



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

@app.post("/api/bytesToPem")
async def bytesConvert(keys: Protocol):
    return {keys.pubkey}

@app.post("/api/sessionStart")
async def init(keys: Protocol):
    ciphertext = kyber.encap(keys.kemalg, keys.pubkey) 
    return {"ciphertext": ciphertext}