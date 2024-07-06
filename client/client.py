import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'kyberpy'))
from kyberpy import kyber
import json
import time
from pymongo import MongoClient, ASCENDING
from fe25519 import fe25519
from ge25519 import ge25519, ge25519_p3
from datetime import datetime
import secrets


class TerminalColors:
    WARNING = '\033[93m'  # Yellow color for warning
    END = '\033[0m'       # Reset to default color



#Server URL
SERVER = "http://localhost:5001"

def connect_local_db(username):
    mongo_host = os.getenv('MONGO_HOST', 'localhost')
    mongo_port = int(os.getenv('MONGO_PORT', '27018'))
    mongo_client = MongoClient(mongo_host, mongo_port)
    db = mongo_client[f"{username}_db"]
    return db


# DOVREBBERO FUNZIONARE
def x25519_from_ed25519_private_bytes(private_bytes):
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

# The private key needs to be a bytes array
def private_ed_to_x(private_key):
    return X25519PrivateKey.from_private_bytes(x25519_from_ed25519_private_bytes(private_key))

def x25519_from_ed25519_public_bytes(public_bytes) -> X25519PublicKey:
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

# The public key needs to be a bytes array
def public_ed_to_x(public_key):
    return X25519PublicKey.from_public_bytes(x25519_from_ed25519_public_bytes(public_key))

# Define a custom encoder for serialization
class PrivateKeyEncoder(json.JSONEncoder):
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

# Custom decoder to deserialize JSON string to Ed25519PrivateKey
def ed25519_private_key_decoder(data):
    private_key_bytes = bytes.fromhex(data)
    # Deserialize private key from bytes
    return ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)


def X25519_private_key_decoder(data):
    private_key_bytes = bytes.fromhex(data)
    # Deserialize private key from bytes
    return X25519PrivateKey.from_private_bytes(private_key_bytes)
    
#read from json file
def read_keys(username):
    db = connect_local_db(username)
    keys_collection = db.keys
    data = keys_collection.find_one({"username":username})
    return data["private_keys"]


#save keys to mongoDB
def export_keys(username,data, keys_collection):
    data = json.dumps(data, cls=PrivateKeyEncoder, indent=4)
    data = json.loads(data)
    keys_collection.insert_one({
        "username" : username,
        "private_keys": data
    })

#Serialize public keys
def public_serialization(key):
    return key.public_bytes(encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw).hex()

#Deserialize public keys
def public_EDdeserialization(hex_key):
    key_bytes = bytes.fromhex(hex_key)
    return Ed25519PublicKey.from_public_bytes(key_bytes)

def public_Xdeserialization(hex_key):
    key_bytes = bytes.fromhex(hex_key)
    return X25519PublicKey.from_public_bytes(key_bytes)


#generate public and private keys
def generate_keys():
    # Mancano identificatori per le chiavi!!! Mi scuddai
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
    

def generate_one_time(username):
    db = connect_local_db(username)
    keys_collection = db.keys
    data = keys_collection.find_one({"username":username})["private_keys"]["private_identity_key"]
    private_identity_key_Ed = ed25519_private_key_decoder(data)
    private_one_time_prekeys = list()
    public_one_time_prekeys = list()
    for i in range(5):
        id = time.time_ns()
        private_one_time_prekeys.append({"key":X25519PrivateKey.generate(), "id": id})
        public_one_time_prekeys.append({"key":public_serialization(private_one_time_prekeys[i]["key"].public_key()), "id": id})
        #Serialize
        private_one_time_prekeys[-1]["key"] = json.dumps(private_one_time_prekeys[-1]["key"], cls=PrivateKeyEncoder, indent=4)
    private_one_time_pqkem_prekeys = list()
    public_one_time_pqkem_prekeys = list()

    for i in range(5):
        id = time.time_ns()
        pqkem = kyber.Kyber512.keygen()
        public_one_time_pqkem_prekeys.append({"key":pqkem[0].hex(), "id": id, "sign":private_identity_key_Ed.sign(pqkem[0]).hex()})
        private_one_time_pqkem_prekeys.append({"key":pqkem[1].hex(), "id": id})
    
    #update locally
    keys_collection.update_one(
        {'username': username},
        {'$push': {'private_keys.private_one_time_prekeys':{"$each":private_one_time_prekeys}, 'private_keys.private_one_time_pqkem_prekeys':{"$each" : private_one_time_pqkem_prekeys}}})

    print(TerminalColors.WARNING + "Keys inserted locally" + TerminalColors.END)
    #update online
    payload = {
        "username": username,
        "otp": public_one_time_prekeys,
        "otpp": public_one_time_pqkem_prekeys
    }
    payload = json.dumps(payload, indent=4)
    url = SERVER + "/new_keys"
    response = requests.post(url, payload,headers = {"Content-Type": "application/json", "Accept": "application/json"})
    if response.status_code == 200:
        print(TerminalColors.WARNING + "New keys uploaded!" + TerminalColors.END)
    else:
        print(TerminalColors.WARNING + "Warning: Error inserting new keys" + TerminalColors.END)


def register(username, password,public_keys):
    url = SERVER + "/register"
    # Mancano gli identifier delle chiavi?
    payload = {
        "username": username,
        "password": password,
        "public_keys": public_keys
    }
    payload = json.dumps(payload, indent=4)
    response = requests.post(url, payload,headers = {"Content-Type": "application/json", "Accept": "application/json"})
    return response

def login(username,password):
    url = SERVER + "/login"
    payload = {
        "username": username,
        "password": password,
     }
    payload = json.dumps(payload, indent=4)
    response = requests.post(url, payload,headers = {"Content-Type": "application/json", "Accept": "application/json"})
    print(response.json())
    if response.status_code == 200:
        if (int(response.json()["otp"])) < 2:
            print(TerminalColors.WARNING + "Warning: few one time keys remaining. Generating new ones" + TerminalColors.END)
            generate_one_time(username)
        if response.json()["prekey_expired"]:
            print(TerminalColors.WARNING + "Warning: curve prekey expired. Generating new one" + TerminalColors.END)
            generate_prekey(username)
        if response.json()["last_resort_expired"]:
            print(TerminalColors.WARNING + "Warning: pqkem prekey expired. Generating new one" + TerminalColors.END)
            generate_last_resort(username)
    return response

def generate_last_resort(username):
    db = connect_local_db(username)
    keys_collection = db.keys
    data = keys_collection.find_one({"username":username})["private_keys"]["private_identity_key"]
    private_identity_key_Ed = ed25519_private_key_decoder(data)
    id = time.time_ns()
    pqkem = kyber.Kyber512.keygen()
    private_last_resort_pqkem_key = {"key":pqkem[1], "id": id}
    public_last_resort_pqkem_key = {"key":pqkem[0].hex(), "id": id, "sign":private_identity_key_Ed.sign(pqkem[0]).hex()}

    #update locally
    keys_collection.update_one(
        {'username': username},
        {'$push': {'private_keys.private_last_resort_pqkem_key': private_last_resort_pqkem_key}})
    print(TerminalColors.WARNING + "New pqkem last resort key inserted locally" + TerminalColors.END)

    #update online
    payload = {
        "username": username,
        "public_last_resort_pqkem_key": public_last_resort_pqkem_key
    }
    payload = json.dumps(payload, indent=4)
    url = SERVER + "/new_keys"
    response = requests.post(url, payload,headers = {"Content-Type": "application/json", "Accept": "application/json"})
    if response.status_code == 200:
        print(TerminalColors.WARNING + "New last resort key uploaded!" + TerminalColors.END)
    else:
        print(TerminalColors.WARNING + "Warning: Error inserting new last resort key" + TerminalColors.END)

def generate_prekey(username):
    db = connect_local_db(username)
    keys_collection = db.keys
    data = keys_collection.find_one({"username":username})["private_keys"]["private_identity_key"]
    private_identity_key_Ed = ed25519_private_key_decoder(data)

    id = time.time_ns()
    private_prekey = {"key": X25519PrivateKey.generate(), "id": id}
    public_prekey = {"key":public_serialization(private_prekey["key"].public_key()), "id" :id}
    public_prekey["sign"] = private_identity_key_Ed.sign(bytes.fromhex(public_prekey["key"])).hex()

    #update locally
    private_prekey["key"] = json.dumps(private_prekey["key"], cls=PrivateKeyEncoder, indent=4)
    keys_collection.update_one(
        {'username': username},
        {'$push': {'private_keys.private_prekey': private_prekey}})

    print(TerminalColors.WARNING + "New curve prekey inserted locally" + TerminalColors.END)

    #update online
    payload = {
        "username": username,
        "public_prekey": public_prekey
    }
    payload = json.dumps(payload, indent=4)
    url = SERVER + "/new_keys"
    response = requests.post(url, payload,headers = {"Content-Type": "application/json", "Accept": "application/json"})
    if response.status_code == 200:
        print(TerminalColors.WARNING + "New curve prekey uploaded!" + TerminalColors.END)
    else:
        print(TerminalColors.WARNING + "Warning: Error inserting new curve prekey" + TerminalColors.END)
    

def fetch_key_bundle(username):
    url = f"{SERVER}/fetch_prekey_bundle/{username}"
    response = requests.get(url)
    return response

def signature_check(key_bundle):
    try:
        public_identity_key = public_EDdeserialization(key_bundle["public_identity_key"])
        public_identity_key.verify(bytes.fromhex(key_bundle["public_prekey"]["sign"]), bytes.fromhex(key_bundle["public_prekey"]["key"]))

        if(key_bundle["public_one_time_pqkem_prekey"] != None):
            public_identity_key.verify(bytes.fromhex(key_bundle["public_one_time_pqkem_prekey"]["sign"]), bytes.fromhex(key_bundle["public_one_time_pqkem_prekey"]["key"]))
        
        else:
            public_identity_key.verify(bytes.fromhex(key_bundle["public_one_time_pqkem_prekey"]["sign"]), bytes.fromhex(key_bundle["public_last_resort_pqkem_key"]["key"]))
        return True
    except InvalidSignature:
        return False

def X3DH_KDF(DHs):
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
    
def send_initial_message(username,destination, keys_collection, chats_collection):
    key_bundle = fetch_key_bundle(destination)
    if key_bundle.status_code != 200:
        print("User not found")
        return
    key_bundle = key_bundle.json()

    if signature_check(key_bundle):
        print("Signature check passed")
        print("Starting chat...")
        # Generate a pqkem encapsulated shared secret
        if key_bundle["public_one_time_pqkem_prekey"] != None:
            pqkem = key_bundle["public_one_time_pqkem_prekey"]
        else:
            pqkem = key_bundle["public_last_resort_pqkem_key"]
        ct, shared_secret = kyber.Kyber512.enc(bytes.fromhex(pqkem["key"]))

        # Generate an ephemeral curve key 
        ephemeral_key = X25519PrivateKey.generate()
        public_ephemeral_key = public_serialization(ephemeral_key.public_key())

        # Fetch private identity key from local database --> FORSE E' DA CAMBIARE
        private_identity_key = keys_collection.find_one({"username": username})["private_keys"]["private_identity_key"]

        # Convert identity key to X25519
        private_identity_key_X = private_ed_to_x(bytes.fromhex(private_identity_key))
        # DH1(IKa, SPKb)
        DH1 = private_identity_key_X.exchange(public_Xdeserialization(key_bundle["public_prekey"]["key"]))
        # DH2(EKa, IKb)
        DH2 = ephemeral_key.exchange(public_ed_to_x(bytes.fromhex(key_bundle["public_identity_key"])))
        # DH3(EKa, SPKb)
        DH3 = ephemeral_key.exchange(public_Xdeserialization(key_bundle["public_prekey"]["key"]))
        if key_bundle["public_one_time_prekey"] != None:
            # DH4(EKa, OPKb)
            curve_one_time = key_bundle["public_one_time_prekey"]
            curve_one_time_id = curve_one_time["id"]
            DH4 = ephemeral_key.exchange(public_Xdeserialization(curve_one_time["key"]))
            sk = X3DH_KDF(DH1 + DH2 + DH3 + DH4 + shared_secret)
        else:
            sk = X3DH_KDF(DH1 + DH2 + DH3 + shared_secret)
            curve_one_time_id = None
        

        # Two identity keys as bytes strings
        public_identity_key_user = bytes.fromhex(public_serialization(private_identity_key_X.public_key()))
        public_identity_key_other_user = bytes.fromhex(public_serialization(public_ed_to_x(bytes.fromhex(key_bundle["public_identity_key"]))))
        # Associated data:
        ad = (public_identity_key_user + public_identity_key_other_user)

        initial_message_plaintext = b"**INITIAL MESSAGE**"
        aesgcm = AESGCM(sk)
        nonce = secrets.token_bytes(32)
        initial_message_ciphertext = (aesgcm.encrypt(nonce, initial_message_plaintext, ad)).hex()
        
        initial_message = {
            "identity_key" : public_identity_key_user.hex(),
            "ephemeral_key" : public_ephemeral_key, # Already in hex
            "cipher_text" : ct.hex(),
            "public_prekey_id" : key_bundle["public_prekey"]["id"],
            "pqkem_id" : pqkem["id"],
            "curve_one_time_id" : curve_one_time_id,
            "initial_message": nonce.hex() + initial_message_ciphertext # Already in hex
        }
        
        # Send initial message to the other user
        payload = {
            "type" : "INIT",
            "sender": username,
            "receiver": destination,
            "message": initial_message,
            "timestamp": time.time()
        }

        payload1 = json.dumps(payload, indent=4)
        url = SERVER + "/send_message"
        response = requests.post(url, payload1,headers = {"Content-Type": "application/json", "Accept": "application/json"})
        if response.status_code != 200:
            print("Error in sending message")
            print(response.text)
            return
        
        # Save INIT message in the local database
        chats_collection.insert_one(payload)

        # Save secret key and associated data in the local database
        keys_collection.update_one(
        {'username': username},
        {'$set': {f"{destination}": {
            "SK" : sk.hex(),
            "AD" : ad.hex()
        }}}  # Create a field for the receiver of chat containing SK and AD
        )
        return (sk,ad)
    else:
        print("Signature check failed")
        print("Aborting chat...")
        return

def handle_initial_message(msg, keys_collection):
    identity_key = msg["message"]["identity_key"]
    ephemeral_key = msg["message"]["ephemeral_key"]
    local_keys = keys_collection.find_one({"username": msg["receiver"]})["private_keys"]
    private_key = ed25519_private_key_decoder(local_keys["private_identity_key"])
    # Dovrebbe aggiornare la prekey ogni tanto, e quindi bisogna considerare l'id
    #public_key_X
    public_identity_key = public_Xdeserialization(msg["message"]["identity_key"]) 
    #ephemeral_key_X
    ephemeral_key = public_Xdeserialization(msg["message"]["ephemeral_key"])
    local_keys = keys_collection.find_one({"username":msg["receiver"]})["private_keys"]
    #private_key_X
    private_key_X = private_ed_to_x(bytes.fromhex(local_keys["private_identity_key"]))

    for key in local_keys["private_prekey"]:
        if key["id"] == msg["message"]["public_prekey_id"]:
            print(key["key"])
            spk = X25519_private_key_decoder(key["key"])
            break

    if msg["message"]["curve_one_time_id"] != None:
      for key in local_keys["private_one_time_prekeys"]:
          if key["id"] == msg["message"]["curve_one_time_id"]:
              opk = X25519_private_key_decoder(key["key"])
              break
    
    pqpk = None
    for key in local_keys["private_last_resort_pqkem_key"]:
        if key["id"] == msg["message"]["pqkem_id"]:
            pqpk = bytes.fromhex(key["key"])
    if pqpk == None:
        for key in local_keys["private_one_time_pqkem_prekeys"]:
          if key["id"] == msg["message"]["pqkem_id"]:
              pqpk = bytes.fromhex(key["key"])
              break
    
    SS = kyber.Kyber512.dec(bytes.fromhex(msg["message"]["cipher_text"]), pqpk)
    # DH1(SPKb,IKa)
    DH1 = spk.exchange(public_identity_key)
    # DH2(IKb,EKa)
    DH2 = private_key_X.exchange(ephemeral_key)
    # DH3(SPKb,EKa)
    DH3 = spk.exchange(ephemeral_key)
    # DH4(OPKb,EKa)
    DH4 = opk.exchange(ephemeral_key)
    sk = X3DH_KDF(DH1 + DH2 + DH3 + DH4 + SS)
    #TODO: deletes the DH values and SS values.
    # Associated data:
    ad = (public_serialization(public_identity_key) + public_serialization(private_key_X.public_key()))
    aesgcm = AESGCM(sk)
    # The nonce is in the first 32 bytes of the ciphertext
    nonce = bytes.fromhex(msg["message"]["initial_message"])[:32]
    encrypted_text = bytes.fromhex(msg["message"]["initial_message"])[32:]
    decrypted_initial_message = aesgcm.decrypt(nonce, encrypted_text,bytes.fromhex(ad))
    if decrypted_initial_message.decode() == "**INITIAL MESSAGE**":
        #print(f"Initial message from {msg['sender']} correctly received")
        # Save secret key and associated data in the local database
        keys_collection.update_one(
        {'username': msg["receiver"]},
        {'$set': {f"{msg['sender']}": {
            "SK" : sk.hex(),
            "AD" : ad
        }}} 
        )
    else:
        print("Initial message failed")
        print("Aborting chat...")
        return



def send_message(msg,sender,receiver, chats_collection, keys_collection ,nonce_dim = 32):
    # Get secret key and associated data from the local database
    local_keys = keys_collection.find_one({"username": sender})
    sk = bytes.fromhex(local_keys[receiver]["SK"])
    ad = bytes.fromhex(local_keys[receiver]["AD"])
    aesgcm = AESGCM(sk)
    nonce = secrets.token_bytes(nonce_dim)
    encrypted_message = aesgcm.encrypt(nonce, msg, ad).hex()
    # Send message to the other user
    payload = {
        "type" : "MSG",
        "sender": sender,
        "receiver": receiver,
        "message": nonce.hex() + encrypted_message,
        "timestamp": time.time()
    }

    #Save on local database
    chats_collection.insert_one(payload)
    if "_id" in payload:
        del payload["_id"]
    #Save on server database
    payload = json.dumps(payload, indent=4)
    url = SERVER + "/send_message"
    response = requests.post(url, payload,headers = {"Content-Type": "application/json", "Accept": "application/json"})
    if response.status_code != 200:
        print("Error in sending message")
        print(response.text)
        return

def decrypt_message(msg,user,other_user,keys_collection, nonce_dim = 32):
    local_keys = keys_collection.find_one({"username": user})
    sk = bytes.fromhex(local_keys[other_user]["SK"])
    ad = bytes.fromhex(local_keys[other_user]["AD"])
    aesgcm = AESGCM(sk)
    nonce = bytes.fromhex(msg["message"])[:nonce_dim]
    message = bytes.fromhex(msg["message"])[nonce_dim:]
    msg["message"] = aesgcm.decrypt(nonce, message,ad)
    return msg

def download_new_messages(username, db):
    payload = {"username": username}
    payload = json.dumps(payload, indent=4)
    request = requests.post(SERVER + "/receive_messages",payload, headers = {"Content-Type": "application/json", "Accept": "application/json"})
    for msg in request.json()["messages"]:
        if msg["type"] == "INIT":
            handle_initial_message(msg,db.keys)
        #Save on local database
        db.chats.insert_one(msg)


def get_active_chats(username, chats_collection):
    list = []
    messages = chats_collection.find({"$or":[{"receiver": username,"type":"INIT"}, {"sender": username,"type":"INIT"}]})
    for message in messages:
        if message["receiver"] == username:
            list.append(message["sender"])
        else:
            list.append(message["receiver"])
    return list


def load_chat(user1, user2, chats_collection):
    return list(chats_collection.find({"$or":[{"receiver": user1,"sender":user2,"type":"MSG"}, {"receiver": user2, "sender": user1, "type":"MSG"}]}).sort("timestamp",ASCENDING))

def show_chat(user1,user2, chats_collection):
    messages = list(chats_collection.find({"$or":[{"receiver": user1,"sender":user2,"type":"MSG"}, {"receiver": user2, "sender": user1, "type":"MSG"}]}).sort("timestamp",ASCENDING))
    for message in messages:
        if message["sender"] == user1:
            print("                 ",message["message"])
            print(datetime.fromtimestamp(message["timestamp"]))
        else:
            print(message["message"])
            print(datetime.fromtimestamp(message["timestamp"]))
        print("")
        print("")





def menu_user(username):
    db = connect_local_db(username)
    keys_collection = db.keys
    chats_collection = db.chats
    print(f"Welcome {username}!")
    print("Main menu\n")
    print("1. Chats")
    print("2. Groups")
    print("0. Back")

    payload = {
        "receiver": username,
        "sender": "giulia"
    }
   
    #print(request.json())

    choice = input("Enter your choice: ")
    if choice == "0":
        return
    if choice == "1":
        print("Active chats\n")
        # Controllare se esistono chat attive
        download_new_messages(username)
        chats = get_active_chats(username)
        for chat in chats:
            print(chat)
        # Altrimenti:
        print("1. New chat")
        print("2. Back")
        choice = input("Enter your choice: ")
        if choice == "1":
            receiver = input("Type the username you want to chat with:")
            print("Starting chat...")
            sk,ad = send_initial_message(username,receiver, keys_collection)
            send_message(b"Hello",username,receiver, chats_collection)
        else:
            for user in chats:
                if choice == user:
                    show_chat(username,choice)
        
        
def main():
    while 1:
        
        print("Welcome to QuantumChat!")
        print("")
        print("Select a choice: ")
        print("1. Login")
        print("2. Register")
        print("0. Exit")

        choice = input()

        if choice == "0":
            exit()
        elif choice == "1":
            print("Login Menu")
            print("")
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            #Hash the password
            digest = hashes.Hash(hashes.SHA256())
            digest.update(password.encode())
            password = digest.finalize()
            password = password.hex()
            #Login
            response = login(username, password)

            if response.status_code == 200:
                menu_user(username)
            else: 
                print(response.text)

        elif choice == "2":
            print("Register Menu")
            print("")
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            #Hash the password
            digest = hashes.Hash(hashes.SHA256())
            digest.update(password.encode())
            password = digest.finalize()
            password = password.hex()
            keys = generate_keys()

            #Register the user on server with his public keys
            response = register(username, password, keys[1])
            db = connect_local_db(username)
            keys_collection = db.keys
            #if the user has been correctly registered, save 
            # private keys locally and go to menu
            if response.status_code == 200:
                export_keys(username,keys[0], keys_collection)
                menu_user(username)  
            else:
                print(response.text)




if __name__ == "__main__":
    main()

'''
# PK = public key, SK = secret key
pk, sk = kyber.Kyber512.keygen()
c, key = kyber.Kyber512.enc(pk)
_key = kyber.Kyber512.dec(c, sk)
print(key == _key)
'''