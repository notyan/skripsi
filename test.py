import timeit
from utils import ecc, pem


level = 1
itr = 100
sk, pk = ecc.keygen(level)
signature = ecc.sign(level, b"TEST", sk)
c, K = ecc.encap(level, pk)
#c_byte = pem.serializeDer(c, 1)
#print(pem.serializeDer(sk, 0))

print(timeit.timeit(lambda: pem.serializeDer(pk, 1), number=itr))
print(timeit.timeit(lambda: pem.serializeECC(pk, 1), number=itr))

# pem.serializeDer(sk, 0)
# pem.serializeECC(sk, 0)
# print("\n")
# pem.serializeDer(pk, 1)
# pem.serializeECC(pk, 1)

