from quantcrypt.kem import Kyber

kem = Kyber()

# Next, we generate a PK and SK pair.
public_key, secret_key = kem.keygen()
print(type(public_key))
# Then, we use the PK to encapsulate the internally 
# generated shared_secret bytes into cipher_text bytes.
cipher_text, shared_secret = kem.encaps(public_key)

# Finally, the secret_key is used to decapsulate the
# original shared_secret from the cipher_text bytes.
shared_secret_copy = kem.decaps(secret_key, cipher_text)

# Check that the shared secrets match
assert shared_secret_copy == shared_secret