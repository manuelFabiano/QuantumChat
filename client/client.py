import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'kyberpy'))
from kyberpy import kyber
import json
import time

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


#save keys to json file
def export_keys(data):
    with open("keys.json","w") as file:
        json.dump(data, file, cls=Ed25519PrivateKeyEncoder, indent=4)

#Serialize public keys
def public_serialization(key):
    return key.public_bytes(encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw).hex()

#generate public and private keys
def generate_keys():
    # Mancano identificatori per le chiavi!!! Mi scuddai
    # Curve keys
    private_identity_key = Ed25519PrivateKey.generate()
    public_identity_key = public_serialization(private_identity_key.public_key())
    id = time.time_ns()
    private_prekey = {"key": Ed25519PrivateKey.generate(), "id": id}
    public_prekey = {"key":public_serialization(private_prekey["key"].public_key()), "id" :id}
    sign_on_prekey = private_identity_key.sign(public_prekey["key"].encode('utf-8')).hex()
    private_one_time_prekeys = list()
    public_one_time_prekeys = list()
    for i in range(5):
        id = time.time_ns()
        private_one_time_prekeys.append({"key":Ed25519PrivateKey.generate(), "id": id})
        public_one_time_prekeys.append({"key":public_serialization(private_one_time_prekeys[i]["key"].public_key()), "id": id})

    # Kyber keys:
    id = time.time_ns()
    private_last_resort_pqkem_key , public_last_resort_pqkem_kyber_key = kyber.Kyber512.keygen()
    private_last_resort_pqkem_key = {"key": private_last_resort_pqkem_key.hex(), "id": id}
    public_last_resort_pqkem_kyber_key = {"key":public_last_resort_pqkem_kyber_key.hex(), "id":id}
    sign_on_last_resort_pqkem_key = private_identity_key.sign(public_last_resort_pqkem_kyber_key["key"].encode('utf-8')).hex()

    private_one_time_pqkem_prekeys = list()
    public_one_time_pqkem_prekeys = list()
    sign_on_one_time_pqkem_prekeys = list()

    for i in range(5):
        id = time.time_ns()
        pqkem = kyber.Kyber512.keygen()
        private_one_time_pqkem_prekeys.append({"key":pqkem[0].hex(), "id": id})
        public_one_time_pqkem_prekeys.append({"key":pqkem[1].hex(), "id": id })
        sign_on_one_time_pqkem_prekeys.append(private_identity_key.sign(pqkem[1]).hex())

    # Json Data structure containing private keys
    private_keys = {
        "private_identity_key": private_identity_key,
        "private_prekey": private_prekey,
        "private_one_time_prekeys" : private_one_time_prekeys,
        "private_last_resort_pqkem_key" : private_last_resort_pqkem_key,
        "private_one_time_pqkem_prekeys" : private_one_time_pqkem_prekeys
    }

    public_keys = {
        "public_identity_key": public_identity_key,
        "public_prekey" :public_prekey,
        "sign_on_prekey" : sign_on_prekey,
        "public_one_time_prekeys" : public_one_time_prekeys,
        "public_last_resort_pqkem_key" : public_last_resort_pqkem_kyber_key,
        "sign_on_last_resort_pqkem_key" : sign_on_last_resort_pqkem_key,
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