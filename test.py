from functools import partial
import timeit
from utils import dilithium, ecc, files, pem,rsaalg

repetition=10
recurrence=10
level = 2
sentences = b"TEST TO SIGN"
rsa_ssk, _ = rsaalg.keygen(level)
rsaSign = partial(rsaalg.sign,level, sentences, rsa_ssk)
rsa_sign_time = timeit.repeat(rsaSign , number=recurrence, repeat=repetition)


ecc_ssk, _ = ecc.keygen(level)
eccSign = partial(ecc.sign, level, sentences, ecc_ssk)
ecc_sign_time = timeit.repeat(eccSign , number=recurrence, repeat=repetition)

print(ecc_sign_time)
print("\n")
print(rsa_sign_time)




