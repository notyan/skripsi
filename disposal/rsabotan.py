import botan3

# Initialize the Botan RNG (Random Number Generator)
rng = botan3.RandomNumberGenerator()

# Generate RSA private key with 2048-bit size
private_key = botan3.PrivateKey.create('RSA', 'modulus_bits=2048', rng)

# Export private key in PEM format
private_pem = private_key.export_private()

# Save the private key to a file
with open("botan_private_key.pem", "wb") as private_file:
    private_file.write(private_pem)

# Export the public key from the private key
public_key = private_key.get_public_key()
public_pem = public_key.export_public()

# Save the public key to a file
with open("botan_public_key.pem", "wb") as public_file:
    public_file.write(public_pem)

print("RSA key pair generated and saved as 'botan_private_key.pem' and 'botan_public_key.pem'")
