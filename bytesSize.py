from ctypes import c_byte
from utils import kyber,dilithium, ecc, rsaalg, pem

#algorithms = ["kyber", "dilithium", 'rsa', "ecc"]
algorithms = ["ecc", "kyber", "dilithium"]
for alg in algorithms:
    for level in range (1,4):
        if alg == "kyber":
            print(f'=========== {alg} Level {level} ===========')
            sk, pk = kyber.keygen(level)
            c, K = kyber.encap(level, pk)

            print(f'sk \tsize {len(sk)}')
            print(f'pk \tsize {len(pk)}')
            print(f'c \tsize {len(c)}')
        elif alg == "dilithium":
            print(f'=========== {alg} Level {level} ===========')
            sk, pk = dilithium.keygen(level)
            signature = dilithium.sign(level, b"TEST", sk)

            print(f'sk \tsize {len(sk)}')
            print(f'pk \tsize {len(pk)}')
            print(f'signature \tsize {len(signature)}')
        elif alg == "ecc":
            print(f'=========== {alg} Level {level} ===========')
            sk, pk = ecc.keygen(level)
            signature = ecc.sign(level, b"TEST", sk)
            c, K = ecc.encap(level, pk)
            c_byte = pem.serializeDer(c, 1)

            print(f'sk \tsize {len(pem.serializeDer(sk, 0).hex())}')
            print(f'pk \tsize {len(pem.serializeDer(pk, 1).hex())}')
            print(f'signature \tsize {len(signature)}')
            print(f'ciphertext \tsize {len(c_byte)}')

        elif alg == "rsa":
            print(f'=========== {alg} Level {level} ===========')
            sk, pk = rsaalg.keygen(level)
            signature = rsaalg.sign(level, b"TEST", sk)
            c, K = rsaalg.encap(level, pk)
            print(f'sk \tsize {len(pem.serializeDer(sk, 0))}')
            print(f'pk \tsize {len(pem.serializeDer(pk, 1))}')
            print(f'signature \tsize {len(signature)}')
            print(f'ciphertext \tsize {len(c)}')
            

