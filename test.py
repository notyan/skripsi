import timeit
from utils import dilithium, ecc, files, pem

ssk = files.reads(True, False, "keys/cl_dilithium")
signature = dilithium.sign(3, b"TEST", ssk)
print(signature[:10])


