from typing import Union
from utils import files, kyber, pem, dilithium, rsaalg
from pydantic import BaseModel
from fastapi import FastAPI

app = FastAPI()

class Protocol(BaseModel):
    isPq: bool
    kemPub: str
    signature: str
    sigLevel: int

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.post("/api/sessionGen")
async def start(keys: Protocol):
    #1. Verify PK KEM
    if keys.isPq :
        #open Client Public Keys
        cl_vk = files.reads(keys.isPq, True, 'keys/dilithium.pub')
        
        #Verify PK using client_vk
        #kempub and signature are sent by hex, so we need to convert it back to bytes
        is_valid = dilithium.verif(keys.sigLevel, bytes.fromhex(keys.kemPub), bytes.fromhex(keys.signature), cl_vk)
    else :
        cl_vk = files.reads(keys.isPq, True, 'keys/rsasig.pub')
        #kempub and signature are sent by hex, so we need to convert it back to bytes
        is_valid = rsaalg.verif(bytes.fromhex(keys.kemPub), bytes.fromhex(keys.signature), cl_vk)

    #2. Generate and Encapsulate K, then sign
    if is_valid :
        if keys.isPq :
            #K Generation and encapsulation
            c, K = kyber.encap(keys.sigLevel, bytes.fromhex(keys.kemPub))
            #Ciphertext Signing Process
            sv_ssk = files.reads(keys.isPq, False, 'keys/sv_dilithium') 
            signature = dilithium.sign(keys.sigLevel, c, sv_ssk)        #Sign
        else:
            #print(bytes.fromhex(keys.kemPub))
            kemPublic_bytes = bytes.fromhex(keys.kemPub)   
            kemPublic_pem = pem.pk_bytes_to_pem(kemPublic_bytes)        #Change bytes to pem
            kemPublic = pem.pem_to_key(kemPublic_pem.encode(), 1)       #Encode pem -> bytes -> instance
            c, K = rsaalg.encap(kemPublic)
            #Open the server signature key, and change from pem  to instance
            sv_ssk = files.reads(keys.isPq, False, 'keys/sv_rsasig') 
            #Ciphertext Signing Process
            signature = rsaalg.sign(c, sv_ssk)
    else: 
        print("Verification Invalid")

    #Sent The signature alongside the ciphertext
    return{"signature" : signature.hex(), "ciphertext" : c.hex()}


@app.get("/api/sig_gen")
def read_item(item_id: int, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}

@app.post("/api/bytesToPem")
async def  bytesConvert(keys: Protocol):
    return {keys.pubkey}



@app.post("/api/sessionStart")
async def start(keys: Protocol):
    ciphertext = kyber.encap(keys.kemalg, keys.pubkey) 
    return {"ciphertext": ciphertext}