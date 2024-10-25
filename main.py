import os
from utils import files, pem, ds, kem
from pydantic import BaseModel
from fastapi import FastAPI, Response

app = FastAPI()

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
    return {"AKE": "Implementation"}

@app.post("/api/sessionGen")
async def start(keys: Protocol):
    #Check is the client VK exists in server
    file_path = f'keys/client/{keys.vk}_vk.pub'
    if not os.path.exists(file_path):
        return Response(content="Client VK not found, Please send it first", status_code=400, media_type="text/plain")
    else:
        #1. Verify PK KEM
        #kempub and signature are sent by hex, so we need to convert it back to bytes
        cl_vk = files.reads(keys.isPq, True, f'keys/client/{keys.vk}_vk')
        is_valid = ds.verif(keys.level, keys.isPq, keys.isRsa, bytes.fromhex(keys.kemPub), bytes.fromhex(keys.signature), cl_vk)

    if is_valid :
        #2. Generate and Encapsulate K
        kemPub = bytes.fromhex(keys.kemPub) if keys.isPq else pem.der_to_key( bytes.fromhex(keys.kemPub), 1)
        c, K = kem.encap(keys.level, keys.isPq, kemPub)
        c_bytes = c if keys.isPq else pem.serializeDer(c, 1)

        #3. Sign c
        filename = f'dil{keys.level}' if keys.isPq else f'rsa{keys.level}' if keys.isRsa else f'ecdsa{keys.level}'
        sv_ssk = files.reads(keys.isPq, False, f'keys/server/{filename}') 
        signature = ds.sign(keys.level, keys.isPq, keys.isRsa, c_bytes, sv_ssk)

        #Sent The signature alongside the ciphertext
        if keys.isTest != 0:
            n = keys.isTest
            return{"validator" : (bytes.fromhex(keys.kemPub)[n:n*2] + 
                   bytes.fromhex(keys.signature)[n:n*2] +
                   signature[n:n*2] + c_bytes[n:n*2] + K ).hex(), 
                   "signature" : signature.hex(), "ciphertext" : c_bytes.hex()
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
    files.writes(True, True, cl_vk_bytes, f"keys/client/{keys.cl_vk[:10]}_vk")      #Write Client VK
    isPq = "dil" in result
    sv_vk = files.reads(isPq, True, "keys/server/" + result)
    sv_vk_bytes = sv_vk if isPq else pem.serializeDer(sv_vk, 1)                     #read server vk
    
    #Send back the Server VK to client
    return {"sv_vk" : sv_vk_bytes.hex()}
