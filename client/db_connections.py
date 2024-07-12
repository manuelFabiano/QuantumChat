import os
from pymongo import MongoClient, ASCENDING
import json
import requests

from key_management import *

#Server URL
SERVER = "http://localhost:5001"


class TerminalColors:
    WARNING = '\033[93m'  # Yellow color for warning
    END = '\033[0m'       # Reset to default color


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

def generate_last_resort(username):
    '''
    Function to generate a new last resort key after expiration
    '''
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
    '''
    Function to generate a new signed prekey after expiration
    '''
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
    
def connect_local_db(username):
    mongo_host = os.getenv('MONGO_HOST', 'localhost')
    mongo_port = int(os.getenv('MONGO_PORT', '27018'))
    mongo_client = MongoClient(mongo_host, mongo_port)
    db = mongo_client[f"{username}_db"]
    return db

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

def check_group(group_name):
    url = SERVER + "/check_group"
    payload = {
        "group_name": group_name
    }
    payload = json.dumps(payload, indent=4)
    response = requests.post(url, payload,headers = {"Content-Type": "application/json", "Accept": "application/json"})
    return response.json()["exists"]

def read_keys(username):
    '''
    Read keys from json file
    '''
    db = connect_local_db(username)
    keys_collection = db.keys
    data = keys_collection.find_one({"username":username})
    return data["private_keys"]
