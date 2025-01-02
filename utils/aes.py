
#TESTING
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
data = "KNASDGJSADJGADLLK"
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

# Pad the data to make its length a multiple of the block size
padder = padding.PKCS7(128).padder()
padded_data = padder.update(data.encode()) + padder.finalize()

# Encrypt the data
encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()

# Decrypt the data
decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
unpadder = padding.PKCS7(128).unpadder()
original_data = unpadder.update(decrypted_data) + unpadder.finalize()


#print(encrypted_data)
#print(original_data)
