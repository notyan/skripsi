from utils import ecc
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

client_sk ,client_pk = ecc.keygen(1)
kem_sk ,kem_pk = ecc.keygen(1)
server_sk ,server_pk = ecc.keygen(1)


shared_key = ecc.encap(kem_sk, server_pk)
print(shared_key)
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(shared_key)

server_shared_key = ecc.encap(server_sk, kem_pk)
print(server_shared_key)
#shared_key = kem_sk.exchange(ec.ECDH(), server_pk.public_key())