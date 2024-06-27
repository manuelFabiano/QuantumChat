import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'kyberpy'))
from kyberpy import kyber
import json
import time
from pymongo import MongoClient



#Server URL
SERVER = "http://localhost:5001"

# MongoDB connection
mongo_host = os.getenv('MONGO_HOST', 'localhost')
mongo_port = int(os.getenv('MONGO_PORT', '27018'))
mongo_client = MongoClient(mongo_host, mongo_port)
db = mongo_client.db
keys_collection = db.keys


# Method for X254519PrivateKey for converting from ed25519 to x25519
@classmethod
def from_ed25519_private_bytes(cls, data):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends.openssl.backend import backend
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric.ed25519 import _Reasons

    if not backend.x25519_supported():
        raise UnsupportedAlgorithm(
            "X25519 is not supported by this version of OpenSSL.",
            _Reasons.UNSUPPORTED_EXCHANGE_ALGORITHM,
        )

    hasher = hashes.Hash(hashes.SHA512())
    hasher.update(data)
    h = bytearray(hasher.finalize())
    # curve25519 clamping
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64

    return backend.x25519_load_private_bytes(h[0:32])

setattr(X25519PrivateKey, 'from_ed25519_private_bytes', from_ed25519_private_bytes)



# Define a custom encoder for serialization
class PrivateKeyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Ed25519PrivateKey) or isinstance(obj, X25519PrivateKey):
            # Serialize private key to bytes in PKCS8 format
            pem_private_key = obj.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            # Convert bytes to hex string and return
            return pem_private_key.hex()
        return super().default(obj)

# Custom decoder to deserialize JSON string to Ed25519PrivateKey
'''DA SISTEMARE'''
def ed25519_private_key_decoder(data):
    if '__Ed25519PrivateKey__' in data:
        private_key_bytes = data['__Ed25519PrivateKey__'].encode('utf-8')
        # Deserialize private key from bytes
        return serialization.load_pem_private_key(private_key_bytes, password=None)
    return data

#read from json file
def read_keys():
      with open("keys.json","r") as file:
          data = json.load(file,object_hook=ed25519_private_key_decoder)
          print(data["private_identity_key"])


#save keys to mongoDB
def export_keys(data):
    data = json.dumps(data, cls=PrivateKeyEncoder, indent=4)
    data = json.loads(data)
    keys_collection.insert_one({
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
    private_identity_key_X = X25519PrivateKey.from_ed25519_private_bytes(private_identity_key_Ed)
    public_identity_key_X = private_identity_key_X.public_key()
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
    private_last_resort_pqkem_key , public_last_resort_pqkem_kyber_key = kyber.Kyber512.keygen()
    private_last_resort_pqkem_key = {"key": private_last_resort_pqkem_key.hex(), "id": id}
    public_last_resort_pqkem_kyber_key = {"key":public_last_resort_pqkem_kyber_key.hex(), "id":id}
    public_last_resort_pqkem_kyber_key["sign"] = private_identity_key_Ed.sign(bytes.fromhex(public_last_resort_pqkem_kyber_key["key"])).hex()

    private_one_time_pqkem_prekeys = list()
    public_one_time_pqkem_prekeys = list()
    sign_on_one_time_pqkem_prekeys = list()

    for i in range(5):
        id = time.time_ns()
        pqkem = kyber.Kyber512.keygen()
        private_one_time_pqkem_prekeys.append({"key":pqkem[0].hex(), "id": id})
        public_one_time_pqkem_prekeys.append({"key":pqkem[1].hex(), "id": id, "sign":private_identity_key_Ed.sign(pqkem[1]).hex()})

    # Json Data structure containing private keys
    private_keys = {
        "private_identity_key": private_identity_key_Ed,
        "private_prekey": private_prekey,
        "private_one_time_prekeys" : private_one_time_prekeys,
        "private_last_resort_pqkem_key" : private_last_resort_pqkem_key,
        "private_one_time_pqkem_prekeys" : private_one_time_pqkem_prekeys
    }

    public_keys = {
        "public_identity_key": public_identity_key_Ed,
        "public_prekey" :public_prekey,
        "public_one_time_prekeys" : public_one_time_prekeys,
        "public_last_resort_pqkem_key" : public_last_resort_pqkem_kyber_key,
        "public_one_time_pqkem_prekeys" : public_one_time_pqkem_prekeys,
        "sign_on_one_time_pqkem_prekeys" : sign_on_one_time_pqkem_prekeys
    }

    export_keys(private_keys)
    return public_keys
    



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
        "password": str(password),
     }
    payload = json.dumps(payload, indent=4)
    response = requests.post(url, payload,headers = {"Content-Type": "application/json", "Accept": "application/json"})
    return response


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
        
    
def initialize_chat(username):
    key_bundle = fetch_key_bundle(username)
    if key_bundle.status_code != 200:
        print("User not found")
        return
    key_bundle = key_bundle.json()

    if signature_check(key_bundle):
        print("Signature check passed")
        print("Starting chat...")
        # Generate a pqkem encapsulated shared secret
        if key_bundle["public_one_time_pqkem_prekey"] != None:
            pqkem = key_bundle["public_one_time_pqkem_prekey"]["key"]
        else:
            pqkem = key_bundle["public_last_resort_pqkem_key"]["key"]
        ct, shared_secret = kyber.Kyber512.enc(bytes.fromhex(pqkem))

        # Generate an ephemeral curve key 
        ephemeral_key = X25519PrivateKey.generate()
        public_ephemeral_key = ephemeral_key.public_key()

        # Ipotizzando di poter deserializzare la chiave privata
        private_identity_key = db.find_one({"username": username})
        # Convert identity key to X25519
        private_identity_key = X25519PrivateKey.from_ed25519_key(private_identity_key)
        DH1 = private_identity_key.exchange(public_Xdeserialization(key_bundle["public_prekey"]["key"]))
        DH2 = ephemeral_key.exchange(public_Xdeserialization(key_bundle[""]["key"]))
        
        
    else:
        print("Signature check failed")
        print("Aborting chat...")
        return


def menu_user(username):
    print(f"Welcome {username}!")
    print("Main menu\n")
    print("1. Chats")
    print("2. Groups")
    print("0. Back")
    choice = input("Enter your choice: ")
    if choice == "0":
        return
    if choice == "1":
        print("Chats\n")
        input("Type the username you want to chat with:")
        # Controllare se esiste già una chat con quell'utente
        # Altrimenti:
        print("1. Start chat")
        print("2. Back")
        choice = input("Enter your choice: ")
        if choice == "1":
            print("Starting chat...")
            initialize_chat(username)
        


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
            public_keys = generate_keys()

            #Register the user
            response = register(username, password, public_keys)

            if response.status_code == 200:
                menu_user(username)



if __name__ == "__main__":
    main()

'''
pk, sk = kyber.Kyber512.keygen()
c, key = kyber.Kyber512.enc(pk)
_key = kyber.Kyber512.dec(c, sk)
print(key == _key)
'''