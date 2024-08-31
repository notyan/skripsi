from typing import Union
from utils import kyber, pem, dilithium, rsaalg
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException

app = FastAPI()

class Protocol(BaseModel):
    #ssk: bytes
    isPq: bool
    kemPub: str
    signature: str
    sigLevel: int


@app.get("/")
def read_root():
    return {"Hello": "World"}

'''
TODO
1. Verify kem pk
2. generate and encapsulate K
3. Sign ciphertext(c)
4. Return back ciphertext, and signature
'''
@app.post("/api/sessionGen")
async def start(keys: Protocol):
    #1. Verify PK KEM
    if keys.isPq == True:
        #open Client Public Keys
        cl_vk_pem = open('keys/dilithium.pub', "r").read()
        cl_vk = pem.pk_pem_to_bytes(cl_vk_pem)
        #verify PK using client_vk
        is_valid = dilithium.verif(keys.sigLevel, bytes.fromhex(keys.kemPub), bytes.fromhex(keys.signature), cl_vk)
    else :
        cl_vk_pem = open('keys/rsasig.pub', "rb").read()
        cl_vk = pem.pem_to_key(cl_vk_pem, 1)
        is_valid = rsaalg.verif(bytes.fromhex(keys.kemPub), bytes.fromhex(keys.signature), cl_vk)

    #2. Generate and Encapsulate K, then sign
    if is_valid == True:
        if keys.isPq == True:
            #K Generation and encapsulation
            c, K = kyber.encap(keys.sigLevel, bytes.fromhex(keys.kemPub))
            #Ciphertext Signing Process
            sv_ssk_pem = open('keys/dilithium', "r").read()             #Open pem from file
            sv_ssk = pem.sk_pem_to_bytes(sv_ssk_pem)                    #Change Pem to bytes
            signature = dilithium.sign(keys.sigLevel, c, sv_ssk)        #Sign
        else:
            #print(bytes.fromhex(keys.kemPub))
            kemPublic_bytes = bytes.fromhex(keys.kemPub)   
            kemPublic_pem = pem.pk_bytes_to_pem(kemPublic_bytes)        #Change bytes to pem
            kemPublic = pem.pem_to_key(kemPublic_pem.encode(), 1)       #Encode pem to bytes -> instance
            c, K = rsaalg.encap(kemPublic)
            #Open the server signature key, and change from pem  to instance
            sv_ssk_pem =  open('keys/rsasig', "rb").read()      #Open pem
            sv_ssk = pem.pem_to_key(sv_ssk_pem, 0)              #Convert to instance
            #Ciphertext Signing Process
            signature = rsaalg.sign(c, sv_ssk)
        
    else: 
        print("Not Valid Reject")

    #Sent The signature alongside the ciphertext
    return{"signature" : signature.hex(), "ciphertext" : c.hex()}


    #print(keys.signature)
    #print( bytes.fromhex(keys.signature))
    #print(type(bytes.fromhex(keys.kemPub)))

    #ciphertext = kyber.encap(keys.kemalg, keys.pubkey) 
    #signature = dilithium.sign(keys.ssk,ciphertext, keys.sigLevel)
    #return {verification}


@app.get("/api/sig_gen")
def read_item(item_id: int, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}

@app.post("/api/bytesToPem")
async def  bytesConvert(keys: Protocol):
    #bytesdata = bytes.fromhex(keys.pubkey)
    #result = pem.pk_bytes_to_pem(keys.pubkey)
    #print(bytes.fromhex(keys.pubkey))
    return {keys.pubkey}



@app.post("/api/sessionStart")
async def start(keys: Protocol):
    ciphertext = kyber.encap(keys.kemalg, keys.pubkey) 
    #signature = dilithium.sign(keys.ssk,ciphertext, keys.sigLevel)
    return {"ciphertext": ciphertext}