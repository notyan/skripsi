
from fastecdsa import keys, curve
from cryptography.hazmat.primitives.asymmetric import ec


priv_key = keys.gen_private_key(curve.brainpoolP256r1)
print(priv_key)
#keys.get_public_key(priv_key, curve.P256)
secret_key = ec.generate_private_key(ec.BrainpoolP256R1())
print(secret_key)
#secret_key.public_key()