import os
from typing import Union
from utils import files, kyber, pem, dilithium, ecc, rsaalg
from pydantic import BaseModel
from fastapi import FastAPI, Response

app = FastAPI()

def find_key(dictionary, value):
    return next((key for key, value in dictionary.items() if value == value), None)

class Protocol(BaseModel):
    isPq: bool
    isTest: int
    isRsa: bool
    kemPub: str
    signature: str
    vk: str
    level: int

class PublicKey(BaseModel):
    cl_vk: str

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.post("/api/sessionGen")
async def start(keys: Protocol):
    #Check is the client VK exists in server
    file_path = f'keys/{keys.vk}_vk.pub'
    if not os.path.exists(file_path):
        return Response(content="Client VK not found, Please send it first", status_code=400, media_type="text/plain")
    else:
        #1. Verify PK KEM
        if keys.isPq :
            #open Client Public Keys
            cl_vk = files.reads(keys.isPq, True, f'keys/{keys.vk}_vk')
            #kempub and signature are sent by hex, so we need to convert it back to bytes
            is_valid = dilithium.verif(keys.level, bytes.fromhex(keys.kemPub), bytes.fromhex(keys.signature), cl_vk)
        else :
            if keys.isRsa:
                cl_vk = files.reads(keys.isPq, True, f'keys/client/{keys.vk}_vk')
                #kempub and signature are sent by hex, so we need to convert it back to bytes
                is_valid = rsaalg.verif(keys.level, bytes.fromhex(keys.kemPub), bytes.fromhex(keys.signature), cl_vk)
            else:
                cl_vk = files.reads(keys.isPq, True, f'keys/client/{keys.vk}_vk')
                #kempub and signature are sent by hex, so we need to convert it back to bytes
                is_valid = ecc.verif(keys.level, bytes.fromhex(keys.kemPub), bytes.fromhex(keys.signature), cl_vk)

    #2. Generate and Encapsulate K, then sign
    if is_valid :
        if keys.isPq :
            #K Generation and encapsulation
            c_bytes, K = kyber.encap(keys.level, bytes.fromhex(keys.kemPub))
            #Ciphertext Signing Process
            sv_ssk = files.reads(keys.isPq, False, f'keys/server/dil{keys.level}') 
            signature = dilithium.sign(keys.level, c_bytes, sv_ssk)
        else:
            kemPublic_bytes = bytes.fromhex(keys.kemPub) 
            kemPublic = pem.der_to_key(kemPublic_bytes,1)
            c, K = ecc.encap(keys.level, kemPublic)
            c_bytes = pem.serializeDer(c, 1)

            #Open the server signature key, and change from pem  to instance
            if keys.isRsa:
                sv_ssk = files.reads(keys.isPq, False, f'keys/server/rsa{keys.level}') 
                signature = rsaalg.sign(keys.level, c_bytes, sv_ssk)
            else:
                sv_ssk = files.reads(keys.isPq, False, f'keys/server/ecdsa{keys.level}') 
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
        return Response(content="Bad request: Invalid Verification", status_code=400, media_type="text/plain")


@app.post("/api/vkExchange")
async def vkExchange(keys: PublicKey):
    keysizes = {
        1312: 'dil1', 1952: 'dil2', 2592: 'dil3', 
        92 : 'ecdsa1',  124: 'ecdsa2', 158 : 'ecdsa3',
        422 : 'rsa1', 998 : 'rsa2', 1958 : 'rsa3',
    }
    #Getting Security and algorithm type based on the public key sent
    result = keysizes[len(bytes.fromhex(keys.cl_vk))]
    cl_vk_bytes = bytes.fromhex(keys.cl_vk)
    
    if "dil" in result:
        #write the Client VK into file
        files.writes(True, True, cl_vk_bytes, f"keys/client/{keys.cl_vk[:10]}_vk")
        #Read server VK
        sv_vk_bytes = files.reads(True, True, "keys/server/" + result)
    else:
        cl_vk = pem.der_to_key(cl_vk_bytes, 1)
        files.writes(False, True,cl_vk, f"keys/client/{keys.cl_vk[:10]}_vk")
        sv_vk = files.reads(False, True, "keys/server/" + result)
        sv_vk_bytes = pem.serializeDer(sv_vk, 1)
    
    #Send back the Server VK to client
    return {"sv_vk" : sv_vk_bytes.hex()}

@app.post("/api/sessionStart")
async def init(keys: Protocol):
    ciphertext = kyber.encap(keys.kemalg, keys.pubkey) 
    return {"ciphertext": ciphertext}

@app.get("/api/sig_gen")
def read_item(item_id: int, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}
