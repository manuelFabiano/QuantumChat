from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import json

private_identity_key = Ed25519PrivateKey.generate()
public_identity_key = private_identity_key.public_key()

# print private key as a string
pem_private_key = private_identity_key.private_bytes(
