from utils import kyber, pem, dilithium
import requests

kemalg = "Kyber512"
sk, pk = kyber.keygen(kemalg)
pk_pem = pem.pk_bytes_to_pem(pk)
pk_bytes = pem.pk_pem_to_bytes(pk_pem)
api_url = "http://127.0.0.1:8000/"
ssk, pk = dilithium.keygen(1)

# #print(len(pk_bytes))
# print(os.urandom(32))
#print(pk_bytes)
#"""

#Test bytes to pem convertion
response = requests.post(api_url + "/api/sessionStart", 
    json={
        #"ssk" :  ssk.hex(), 
        "pubkey": pk_bytes.hex(),
        "kemalg": kemalg,
        #"sigLevel": 1,
        },
    headers={"Content-Type": "application/json"},
)
#print(pem.pk_bytes_to_pem(pk_bytes.hex()))
print(pk_bytes)
#print(type(pk_bytes.hex()))
#print(response.json())

#assert pk_bytes == bytes.fromhex(response.json()[0])
#"""

#print(response.json())
#print(bytes.fromhex(response.json().get("result")))
# ciphertext, shared_key = kyber.encap(kemalg, pk_bytes)
# print(len(shared_key))


# assert pk_bytes == 1
#print(type(sk),  len(sk), sk[:10].hex())
#print(type(pk), len(pk))
