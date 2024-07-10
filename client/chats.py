#Server URL
SERVER = "http://localhost:5001"


import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime
import time
import json
import secrets
from pymongo import ASCENDING
from key_management import *




def send_initial_message(username,destination, keys_collection, chats_collection, type, key_group = None, group_name = None):
    key_bundle = fetch_key_bundle(destination)
    if key_bundle.status_code != 200:
        print(f"User {destination} not found")
        return -1
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
            "initial_message": nonce.hex() + initial_message_ciphertext, # Already in hex
        }
        if(type=="INIT_GROUP"):
            initial_message["key_group"] = aesgcm.encrypt(nonce, key_group, ad).hex()
    
        
        # Send initial message to the other user
        payload = {
            "type" : type,
            "sender": username,
            "receiver": destination,
            "message": initial_message,
            "timestamp": time.time()
        }
        if(type=="INIT_GROUP"):
            payload["group_name"] = group_name

        payload1 = json.dumps(payload, indent=4)
        url = SERVER + "/send_message"
        response = requests.post(url, payload1,headers = {"Content-Type": "application/json", "Accept": "application/json"})
        if response.status_code != 200:
            print("Error in sending message")
            print(response.text)
            return -1
        
        # Save INIT message in the local database
        chats_collection.insert_one(payload)

        if(type=="INIT"):
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
            keys_collection.update_one(
            {'username': username},
            {'$set': {f"{group_name}": {
                "SK" : key_group.hex(),
                "AD" : None
            }}}  # Create a field for the receiver of chat containing SK and AD
            )
            return (sk,ad)
    else:
        print("Signature check failed")
        print("Aborting chat...")
        return -1

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
    else:
        opk = None

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
    if opk != None:
        # DH4(OPKb,EKa)
        DH4 = opk.exchange(ephemeral_key)
        sk = X3DH_KDF(DH1 + DH2 + DH3 + DH4 + SS)
    else:
        sk = X3DH_KDF(DH1 + DH2 + DH3 + SS)
        
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
        if msg["type"] == "INIT":
            keys_collection.update_one(
            {'username': msg["receiver"]},
            {'$set': {f"{msg['sender']}": {
                "SK" : sk.hex(),
                "AD" : ad
            }}} 
            )
        else:
            group_key =  aesgcm.decrypt(nonce, bytes.fromhex(msg["message"]["key_group"]),bytes.fromhex(ad))
            keys_collection.update_one(
            {'username': msg["receiver"]},
            {'$set': {f"{msg['group_name']}": {
                "SK" : group_key.hex(),
                "AD" : None
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
    if local_keys[receiver]["AD"] != None:
        ad = bytes.fromhex(local_keys[receiver]["AD"])
    else:
        ad = None
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
    if local_keys[other_user]["AD"] != None:
        ad = bytes.fromhex(local_keys[other_user]["AD"])
    else:
        ad = None
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
        if msg["type"] == "INIT" or msg["type"] == "INIT_GROUP":
            handle_initial_message(msg,db.keys)
        #Save on local database
        db.chats.insert_one(msg)
    groups = list(get_active_groups(username,db.chats))
    request = requests.post(SERVER + "/receive_group_messages", json.dumps({"username": username, "groups": groups}), headers = {"Content-Type": "application/json", "Accept": "application/json"})
    for msg in request.json()["messages"]:
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

def create_group(username, name, members,keys_collection, chats_collection):
    group_key = secrets.token_bytes(32)
    for member in members:
        if send_initial_message(username,member, keys_collection, chats_collection, 'INIT_GROUP', group_key, name) == -1:
            return -1

    

def get_active_groups(username, chats_collection):
    result = set()
    groups = chats_collection.find({"$or":[{"receiver": username,"type":"INIT_GROUP"}, {"sender": username,"type":"INIT_GROUP"}]})
    for group in groups:
        result.add(group["group_name"])
    return result


def load_chat(user1, user2, chats_collection):
    return list(chats_collection.find({"$or":[{"receiver": user1,"sender":user2,"type":"MSG"}, {"receiver": user2, "sender": user1, "type":"MSG"}]}).sort("timestamp",ASCENDING))


def load_group(group, chats_collection):
    return list(chats_collection.find({"receiver": group,"type":"MSG"}).sort("timestamp",ASCENDING))



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