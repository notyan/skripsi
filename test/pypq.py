# Available: hqc_128, hqc_192, hqc_256,
# kyber512, kyber768, kyber1024,
# mceliece348864, mceliece460896,
# mceliece6688128, mceliece6960119, mceliece8192128
from pqc.kem import kyber512 as kemalg


# 1. Keypair generation
pk, sk = kemalg.keypair()
print(pk)

# 2. Key encapsulation
ss, kem_ct = kemalg.encap(pk)


# 3. Key de-encapsulation
ss_result = kemalg.decap(kem_ct, sk)
assert ss_result == ss