from ctypes import c_byte
from utils import kyber,dilithium, ecc, rsaalg, pem

algorithms = ["dilithium", "kyber", "ecc", "rsa"]
#algorithms = ["ecc", "kyber", "dilithium"]
algorithms = ["ecc", "dilithium"]
print('alg ,level ,sk ,pk ,c ,K ,sig')
for alg in algorithms:
    for level in range (1,4):
        if alg == "kyber":
            sk, pk = kyber.keygen(level)
            c, K = kyber.encap(level, pk)

            print(f'{alg} ,{level} ,{len(sk)} ,{len(pk)} ,{len(c)} ,{len(K)} ,-')
        elif alg == "dilithium":
            sk, pk = dilithium.keygen(level)
            signature = dilithium.sign(level, b"TEST", sk)

            print(f'{alg[:3]} ,{level} ,{len(sk)} ,{len(pk)} ,- ,- ,{len(signature)}')
        elif alg == "ecc":
            sk, pk = ecc.keygen(level)
            signature = ecc.sign(level, b"TasdasdsdasdsadsaESTTasdasdsdasdsadsaESTTasdasdsdasdsadsaESTTasdasdsdasdsadsaESTTasdasdsdasdsadsaESTTasdasdsdasdsadsaEST", sk)
            c, K = ecc.encap(level, pk)
            c_byte = pem.serializeDer(c, 1)

            print(f'{alg[:3]} ,{level} ,{len(pem.serializeDer(sk, 0))} ,{len(pem.serializeDer(pk, 1))} ,{len(c_byte)} ,{len(K)} ,{len(signature)}')

        elif alg == "rsa":
            sk, pk = rsaalg.keygen(level)
            signature = rsaalg.sign(level, b"TEST", sk)
            c, K = rsaalg.encap(level, pk)
            
            print(f'{alg[:3]} ,{level} ,{len(pem.serializeDer(sk, 0))} ,{len(pem.serializeDer(pk, 1))} ,{len(c)} ,{len(K)} ,{len(signature)}')
            

