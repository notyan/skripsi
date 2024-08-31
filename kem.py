from utils import kyber, pem
import requests


kemalg = "Kyber512"
sk, pk = kyber.keygen(kemalg)
pk_pem = pem.pk_bytes_to_pem(pk)
pk_bytes = pem.pk_pem_to_bytes(pk_pem)


# ciphertext, shared_key = kyber.encap(kemalg, pk_bytes)
# print(len(shared_key))


# assert pk_bytes == 1
#print(type(sk),  len(sk), sk[:10].hex())
#print(type(pk), len(pk))
