# Signature Python example

import oqs
import time
from pprint import pprint

sigs = oqs.get_enabled_sig_mechanisms()
# pprint(sigs, compact=True)

message = "This is the message to sign".encode()

# Create signer and verifier with sample signature mechanisms
sigalg = "Dilithium2"
with oqs.Signature(sigalg) as signer:
    with oqs.Signature(sigalg) as verifier:
        # Signer generates its keypair
        start_time = time.time()
        signer_public_key = signer.generate_keypair()
        print("--- %s seconds ---" % (time.time() - start_time))

        # Optionally, the secret key can be obtained by calling export_secret_key()
        # and the signer can later be re-instantiated with the key pair:
        # secret_key = signer.export_secret_key()

        # Store key pair, wait... (session resumption):
        # signer = oqs.Signature(sigalg, secret_key)

        # Signer signs the message
        
        start_time = time.time()
        signature = signer.sign(message)
        print("--- %s seconds ---" % (time.time() - start_time))

        # Verifier verifies the signature
        start_time = time.time()
        is_valid = verifier.verify(message, signature, signer_public_key)
        print("--- %s seconds ---" % (time.time() - start_time))

        print("\nValid signature?", is_valid)