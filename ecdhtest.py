from utils import aes, kyber, pem, dilithium, rsaalg, ecc
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

level = 1

usk,upk = ecc.keygen(level)
ssk,spk = ecc.keygen(level)
ask,apk = ecc.keygen(level)


c, ecc_sk = ecc.encap(spk,level)
c_bytes = pem.serialize(c, 1)
dsk = ecc.decap(ask,c_bytes)


print (ecc_sk.hex())
print(dsk.hex())

rsa_secret , rsa_public = rsaalg.keygen(level)
c, rsa_sk = rsaalg.encap(rsa_public)
#print(c.hex())

kyber_secret , kyber_public = kyber.keygen(level)
c, kyber_sk = kyber.encap(level, kyber_public)

def aesEncrypt(text, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()

    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return ct, iv

def aesDecrypt(ct,key,iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return  plaintext.decode()


aes_key = [ ecc_sk, rsa_sk, kyber_sk]
for keys in aes_key:
    ct, iv = aesEncrypt("THIS IS JUST A TEXT I USE TO TEST THE SHARED SERET KEY CREATED USING EACH ALGORITHM", keys)
    print(aesDecrypt(ct,keys,iv))

