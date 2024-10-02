from tinyec import registry
import secrets

curve = registry.get_curve('brainpoolP256r1')
privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g
# print(f"Private key: {privKey}")
# print(f"Public key: ({pubKey.x}, {pubKey.y})")

print(registry.EC_CURVE_REGISTRY.keys())