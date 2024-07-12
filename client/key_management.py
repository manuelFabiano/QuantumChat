from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.backends.openssl.backend import backend
from fe25519 import fe25519
from ge25519 import ge25519, ge25519_p3

import sys
import os
import json
import time
import requests
sys.path.append(os.path.join(os.path.dirname(__file__), 'kyberpy'))
from kyberpy import kyber



class TerminalColors:
    WARNING = '\033[93m'  # Yellow color for warning
    END = '\033[0m'       # Reset to default color

#Server URL
SERVER = "http://localhost:5001"


def x25519_from_ed25519_private_bytes(private_bytes):
    '''Function to return a X25519 private key from ED25519 as an array of bytes.
    '''
    if not backend.x25519_supported():
        raise UnsupportedAlgorithm(
            "X25519 is not supported by this version of OpenSSL.",
            _Reasons.UNSUPPORTED_EXCHANGE_ALGORITHM,
        )

    hasher = hashes.Hash(hashes.SHA512())
    hasher.update(private_bytes)
    h = bytearray(hasher.finalize())
    # curve25519 clamping
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64

    return h[0:32]

def private_ed_to_x(private_key):
    '''This function is used to convert a X25519 private key to a ED25519 private key

       The private key needs to be a bytes array 
    '''
    return X25519PrivateKey.from_private_bytes(x25519_from_ed25519_private_bytes(private_key))

def x25519_from_ed25519_public_bytes(public_bytes) -> X25519PublicKey:
    '''Function to return a X25519 public key from ED25519 as an array of bytes.
    '''
    if not backend.x25519_supported():
        raise UnsupportedAlgorithm(
            "X25519 is not supported by this version of OpenSSL.",
            _Reasons.UNSUPPORTED_EXCHANGE_ALGORITHM,
        )

    # This is libsodium's crypto_sign_ed25519_pk_to_curve25519 translated into
    # the Pyton module ge25519.
    if ge25519.has_small_order(public_bytes) != 0:
        raise ValueError("Doesn't have small order")

    # frombytes in libsodium appears to be the same as
    # frombytes_negate_vartime; as ge25519 only implements the from_bytes
    # version, we have to do the root check manually.
    A = ge25519_p3.from_bytes(public_bytes)
    if A.root_check:
        raise ValueError("Root check failed")

    if not A.is_on_main_subgroup():
        raise ValueError("It's on the main subgroup")

    one_minus_y = fe25519.one() - A.Y
    x = A.Y + fe25519.one()
    x = x * one_minus_y.invert()

    return bytes(x.to_bytes())

def public_ed_to_x(public_key):
    '''This function is used to convert a X25519 public key to a ED25519 public key

       The private key needs to be a bytes array 
    '''
    return X25519PublicKey.from_public_bytes(x25519_from_ed25519_public_bytes(public_key))

class PrivateKeyEncoder(json.JSONEncoder):
    '''
    Custom Encoder for ED25519 and X25519 private keys serialization
    '''
    def default(self, obj):
        if isinstance(obj, Ed25519PrivateKey) or isinstance(obj, X25519PrivateKey):
            pem_private_key = obj.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            # Convert bytes to hex string and return
            return pem_private_key.hex()
        return super().default(obj)


def ed25519_private_key_decoder(data):
    '''
    Custom decoder to deserialize JSON string to Ed25519 PrivateKey
    '''
    private_key_bytes = bytes.fromhex(data)
    # Deserialize private key from bytes
    return ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)


def X25519_private_key_decoder(data):
    '''
    Custom decoder to deserialize JSON string to X25519 PrivateKey
    '''
    private_key_bytes = bytes.fromhex(data)
    # Deserialize private key from bytes
    return X25519PrivateKey.from_private_bytes(private_key_bytes)
    




def export_keys(username,data, keys_collection):
    '''
    Save private keys on local MongoDB
    '''
    data = json.dumps(data, cls=PrivateKeyEncoder, indent=4)
    data = json.loads(data)
    keys_collection.insert_one({
        "username" : username,
        "private_keys": data
    })


def public_serialization(key):
    '''
    Serialize public keys
    '''
    return key.public_bytes(encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw).hex()


def public_EDdeserialization(hex_key):
    '''
    Deserialize ED25519 public keys
    '''
    key_bytes = bytes.fromhex(hex_key)
    return Ed25519PublicKey.from_public_bytes(key_bytes)

def public_Xdeserialization(hex_key):
    '''
    Deserialize X25519 public keys
    '''
    key_bytes = bytes.fromhex(hex_key)
    return X25519PublicKey.from_public_bytes(key_bytes)



def generate_keys():
    '''
    Function to generate public and private keys
    '''
    # Curve keys
    private_identity_key_Ed = Ed25519PrivateKey.generate()
    public_identity_key_Ed = public_serialization(private_identity_key_Ed.public_key())
    id = time.time_ns()
    private_prekey = {"key": X25519PrivateKey.generate(), "id": id}
    public_prekey = {"key":public_serialization(private_prekey["key"].public_key()), "id" :id}
    public_prekey["sign"] = private_identity_key_Ed.sign(bytes.fromhex(public_prekey["key"])).hex()
    private_one_time_prekeys = list()
    public_one_time_prekeys = list()
    for i in range(5):
        id = time.time_ns()
        private_one_time_prekeys.append({"key":X25519PrivateKey.generate(), "id": id})
        public_one_time_prekeys.append({"key":public_serialization(private_one_time_prekeys[i]["key"].public_key()), "id": id})

    # Kyber keys:
    id = time.time_ns()
    public_last_resort_pqkem_kyber_key, private_last_resort_pqkem_key = kyber.Kyber512.keygen()
    private_last_resort_pqkem_key = {"key": private_last_resort_pqkem_key.hex(), "id": id}
    public_last_resort_pqkem_kyber_key = {"key":public_last_resort_pqkem_kyber_key.hex(), "id":id}
    public_last_resort_pqkem_kyber_key["sign"] = private_identity_key_Ed.sign(bytes.fromhex(public_last_resort_pqkem_kyber_key["key"])).hex()

    private_one_time_pqkem_prekeys = list()
    public_one_time_pqkem_prekeys = list()

    for i in range(5):
        id = time.time_ns()
        pqkem = kyber.Kyber512.keygen()
        public_one_time_pqkem_prekeys.append({"key":pqkem[0].hex(), "id": id, "sign":private_identity_key_Ed.sign(pqkem[0]).hex()})
        private_one_time_pqkem_prekeys.append({"key":pqkem[1].hex(), "id": id})
        

    # Json Data structure containing private keys and user informations
    private_keys = {
        "private_identity_key": private_identity_key_Ed,
        "private_prekey": [private_prekey],
        "private_one_time_prekeys" : private_one_time_prekeys,
        "private_last_resort_pqkem_key" : [private_last_resort_pqkem_key],
        "private_one_time_pqkem_prekeys" : private_one_time_pqkem_prekeys
    }

    public_keys = {
        "public_identity_key": public_identity_key_Ed,
        "public_prekey" :public_prekey,
        "public_one_time_prekeys" : public_one_time_prekeys,
        "public_last_resort_pqkem_key" : public_last_resort_pqkem_kyber_key,
        "public_one_time_pqkem_prekeys" : public_one_time_pqkem_prekeys,
    }

    # E' necessario restituire anche le chiavi private?
    return (private_keys,public_keys)
    


def fetch_key_bundle(username):
    '''
    Function to get public keys of a user
    '''
    url = f"{SERVER}/fetch_prekey_bundle"
    payload = json.dumps({"username":username})
    response = requests.post(url, payload,headers = {"Content-Type": "application/json", "Accept": "application/json"})
    return response

def signature_check(key_bundle):
    '''
    Function to ckeck signature of received keys
    '''
    try:
        public_identity_key = public_EDdeserialization(key_bundle["public_identity_key"])
        public_identity_key.verify(bytes.fromhex(key_bundle["public_prekey"]["sign"]), bytes.fromhex(key_bundle["public_prekey"]["key"]))

        if(key_bundle["public_one_time_pqkem_prekey"] != None):
            public_identity_key.verify(bytes.fromhex(key_bundle["public_one_time_pqkem_prekey"]["sign"]), bytes.fromhex(key_bundle["public_one_time_pqkem_prekey"]["key"]))
        else:
            public_identity_key.verify(bytes.fromhex(key_bundle["public_last_resort_pqkem_key"]["sign"]), bytes.fromhex(key_bundle["public_last_resort_pqkem_key"]["key"]))
        return True
    except InvalidSignature:
        return False

def X3DH_KDF(DHs):
    '''
    Key derivation function
    '''
    KDF_F = b'\xff' * 32
    km = KDF_F + DHs
    salt = b'\x00' * 32
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'QuantumChat_CURVE25519_SHA-256_CRYSTALS-KYBER-512',
    )
    return hkdf.derive(km)
