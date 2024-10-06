from utils import dilithium, pem, rsaalg, ecc,kyber, files



output = "keys/ecctest"
message = b"TEST"
ssk, vk = ecc.keygen(1)
files.writes(False, False, ssk, output)
files.writes(False, True, vk, output)

signature = ecc.sign(1, message , ssk)

ssk_load= files.reads(False, False, output)
vk_load = files.reads(False, True, output)

print(pem.serialize(ssk, 0))
print(pem.serialize(ssk_load, 0))

print(ecc.verif(1, message, signature, vk_load))