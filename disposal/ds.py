import utils.dilithium as dilithium
import utils.pem as pem

sk, pk = dilithium.keygen(1)
pk_pem = pem.pk_bytes_to_pem(pk)
pk_bytes = pem.pk_pem_to_bytes(pk_pem)
