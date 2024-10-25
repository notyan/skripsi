from functools import partial
from line_profiler import profile
import timeit
from utils import dilithium, ecc, files, pem,rsaalg
from cryptography.hazmat.primitives import serialization


@profile
def load():
    ssk = files.reads(False, False, "keys/ecdsa3")
    vk_read = files.reads(False, True, "keys/ecdsa3")
    vk_regen = ssk.public_key()

load()


