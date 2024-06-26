import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'kyberpy'))
from kyberpy import kyber
import json

#Server URL
SERVER = "http://flask-server:5000"



# Define a custom encoder for serialization
class Ed25519PrivateKeyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Ed25519PrivateKey):
            # Serialize private key to bytes in PKCS8 format
            pem_private_key = obj.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            # Convert bytes to string and return
            return pem_private_key.decode('utf-8')
        return super().default(obj)

# Custom decoder to deserialize JSON string to Ed25519PrivateKey
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


#save keys to json file
def export_keys(data):
    with open("keys.json","w") as file:
        json.dump(data, file, cls=Ed25519PrivateKeyEncoder, indent=4)


#generate public and private keys
def generate_keys():
    # Mancano identificatori per le chiavi!!! Mi scuddai
    # Curve keys
    private_identity_key = Ed25519PrivateKey.generate()
    public_identity_key = private_identity_key.public_key()
    private_prekey = Ed25519PrivateKey.generate()
    public_prekey = private_prekey.public_key()
    # La firma deve essere fatta con la identity key? Si
    sign_on_prekey = private_identity_key.sign(public_prekey.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
    ))
    private_one_time_prekeys = list()
    public_one_time_prekeys = list()
    for i in range(5):
        private_one_time_prekeys.append(Ed25519PrivateKey.generate())
        public_one_time_prekeys.append(private_one_time_prekeys[i].public_key())

    # Kyber keys:
    private_last_resort_pqkem_key , public_last_resort_pqkem_kyber_key = kyber.Kyber512.keygen()
    sign_on_last_resort_pqkem_key = private_identity_key.sign(public_last_resort_pqkem_kyber_key)

    private_one_time_pqkem_prekeys = list()
    public_one_time_pqkem_prekeys = list()
    sign_on_one_time_pqkem_prekeys = list()

    for i in range(5):
        pqkem = kyber.Kyber512.keygen()
        private_one_time_pqkem_prekeys.append(pqkem[0])
        public_one_time_pqkem_prekeys.append(pqkem[1])
        sign_on_one_time_pqkem_prekeys.append(private_identity_key.sign(pqkem[1]))

    # Json Data structure containing private keys
    private_keys = {
        "private_identity_key": private_identity_key,
        "private_prekey": private_prekey,
        "private_one_time_prekeys" : private_one_time_prekeys,
        "private_last_resort_pqkem_key" : str(private_last_resort_pqkem_key),
        "private_one_time_pqkem_prekeys" : str(private_one_time_pqkem_prekeys)
    }

    public_keys = {
        "public_identity_key": public_identity_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw),
        "public_prekey" : public_prekey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw),
        "sign_on_prekey" : sign_on_prekey,
        "public_one_time_prekeys" : [key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw) for key in public_one_time_prekeys ],
        "public_last_resort_pqkem_key" : public_last_resort_pqkem_kyber_key,
        "sign_on_last_resort_pqkem_key" : sign_on_last_resort_pqkem_key,
        "public_one_time_pqkem_prekeys" : [key for key in public_one_time_pqkem_prekeys],
        "sign_on_one_time_pqkem_prekeys" : [sign for sign in sign_on_one_time_pqkem_prekeys]
    }

    export_keys(private_keys)
    return public_keys
    



def register(username, password,public_keys):
    url = SERVER + "/register"
    # Mancano gli identifier delle chiavi?
    payload = {
        "username": username,
        "password": str(password),
        "public_keys": {
            "public_identity_key": str(public_keys["public_identity_key"]),
            "public_prekey" : str(public_keys["public_prekey"]),
            "sign_on_prekey" : str(public_keys["sign_on_prekey"]),
            "public_one_time_prekeys" : [str(key) for key in public_keys["public_one_time_prekeys"] ],
            "public_last_resort_pqkem_key" : str(public_keys["public_last_resort_pqkem_key"]),
            "sign_on_last_resort_pqkem_key" : str(public_keys["sign_on_last_resort_pqkem_key"]),
            "public_one_time_pqkem_prekeys" : [str(key) for key in public_keys["public_one_time_pqkem_prekeys"]],
            "sign_on_one_time_pqkem_prekeys" : [str(sign) for sign in public_keys["sign_on_one_time_pqkem_prekeys"]]
        }
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
    return response.json()

def signature_check(key_bundle):
    try:
        public_identity_key = Ed25519PublicKey.from_public_bytes(bytes(key_bundle["public_identity_key"]))
        public_prekey = Ed25519PublicKey.from_public_bytes(bytes(key_bundle["public_prekey"]))
        public_identity_key.verify(bytes(key_bundle["sign_on_prekey"]), public_prekey)

        if(key_bundle["public_one_time_pqkem_prekey"] != None):
            public_identity_key.verify(bytes(key_bundle["sign_on_one_time_pqkem_prekey"]),bytes(key_bundle["public_one_time_pqkem_prekey"]))
        
        else:
            public_identity_key.verify(bytes(key_bundle["sign_on_last_resort_pqkem_key"]), bytes(key_bundle["public_last_resort_pqkem_key"]))
        return True
    except InvalidSignature:
        return False
        
    




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
        print("Chats")
        


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
        
            public_keys = generate_keys()

            #Register the user
            response = register(username, password, public_keys)

            if response.status_code == 200:
                menu_user(username)
        elif choice == "3":
            user = input("Inserisci username: ")
            key_bundle = fetch_key_bundle(user)
            print(signature_check(key_bundle))



if __name__ == "__main__":
    main()

'''
pk, sk = kyber.Kyber512.keygen()
c, key = kyber.Kyber512.enc(pk)
_key = kyber.Kyber512.dec(c, sk)
print(key == _key)
'''