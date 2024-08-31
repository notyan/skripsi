from typing import Union
from utils import kyber, pem, dilithium
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException

app = FastAPI()

class Protocol(BaseModel):
    #ssk: bytes
    kemalg: str
    pubkey: str
    # sigLevel: int


@app.get("/")
def read_root():
    return {"Hello": "World"}

'''
TODOLIST
Create API to generate public key and encap
'''
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
