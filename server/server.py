from flask import Flask, request, jsonify
from pymongo import MongoClient
import binascii
import os
import time

app = Flask(__name__)

# MongoDB connection
mongo_host = os.getenv('MONGO_HOST', 'localhost')
mongo_port = int(os.getenv('MONGO_PORT', '27017'))
mongo_client = MongoClient(mongo_host, mongo_port)
db = mongo_client.db
keys_collection = db.keys
chats_collection = db.chats


@app.route('/login',methods=['POST'])
def login():
    data = request.get_json()

    try:
        username = data['username']
        password = data['password']

         #Check if the username and password are correct
        if keys_collection.find_one({'username': username, 'password': password}):
             return jsonify({'message': 'Successfully login!'}), 200
        else:
            return jsonify({'error': 'Wrong username and/or password'}), 400

    except KeyError as e:
        return jsonify({'error': 'Wrong data format: {}'.format(str(e))}), 400



@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    try:
        username = data['username']
        password = data['password']
        public_identity_key= data["public_keys"]["public_identity_key"]
        public_prekey= data["public_keys"]["public_prekey"]
        public_one_time_prekeys= data["public_keys"]["public_one_time_prekeys"]
        public_last_resort_pqkem_key = data["public_keys"]["public_last_resort_pqkem_key"]
        public_one_time_pqkem_prekeys = data["public_keys"]["public_one_time_pqkem_prekeys"]

        #Check if the username is already registered
        if keys_collection.find_one({'username': username}):
            return jsonify({'error': 'Username already registered!'}), 400

        #Save user on MongoDB
        keys_collection.insert_one({
            'username': username,
            'password': password,
            "public_keys":{
                "public_identity_key": public_identity_key,
                "public_prekey" : public_prekey,
                "public_one_time_prekeys" : public_one_time_prekeys,
                "public_last_resort_pqkem_key" : public_last_resort_pqkem_key,
                "public_one_time_pqkem_prekeys" : public_one_time_pqkem_prekeys,
            }
        })

        return jsonify({'message': 'Successfully registered user!'}), 200

    except KeyError as e:
        return jsonify({'error': 'Wrong data format: {}'.format(str(e))}), 400


# Function that fetch the prekey bundle of a user from the database
@app.route('/fetch_prekey_bundle/<username>', methods=['GET'])
def fetch_prekey_bundle(username):
    user = keys_collection.find_one({"username": username})
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    public_keys = user.get("public_keys", {})
    
    # Get user keys:
    public_identity_key = public_keys.get("public_identity_key")
    public_prekey = public_keys.get("public_prekey")
    
    # Get pqkem keys:
    public_one_time_pqkem_prekey_list = public_keys.get("public_one_time_pqkem_prekeys", [])

    if len(public_one_time_pqkem_prekey_list) > 0:
        public_one_time_pqkem_prekey = public_one_time_pqkem_prekey_list[0]
        # Pop the keys from the database
        keys_collection.update_one(
            {"username": username},
            {"$pop": {
                "public_keys.public_one_time_pqkem_prekeys": -1
            }}
        )
        public_last_resort_pqkem_key = None
    else:
        public_one_time_pqkem_prekey = None
        public_last_resort_pqkem_key = public_keys.get("public_last_resort_pqkem_key")
    
    # Get one time curve keys:
    public_one_time_prekey_list = public_keys.get("public_one_time_prekeys", [])
    
    if len(public_one_time_prekey_list) > 0:
        public_one_time_prekey = public_one_time_prekey_list[0]
        # Pop the keys from the database
        keys_collection.update_one(
            {"username": username},
            {"$pop": {"public_keys.public_one_time_prekeys": -1}}
        )
    else:
        public_one_time_prekey = None
    
    prekey_bundle = {
        "public_identity_key": public_identity_key,
        "public_prekey": public_prekey,
        "public_one_time_prekey": public_one_time_prekey,
        "public_one_time_pqkem_prekey": public_one_time_pqkem_prekey,
        "public_last_resort_pqkem_key": public_last_resort_pqkem_key
    } 
    return jsonify(prekey_bundle), 200

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    print(data)
    try:
        sender = data["sender"]
        receiver = data["receiver"]
        message = data["message"]

        #Save message on MongoDB
        chats_collection.insert_one({
            "sender": sender,
            "receiver": receiver,
            "message": message,
            "timestamp": time.time()
        })
        # Da aggiungere la verifica che il receiver sia registrato

        return jsonify({'message': 'Message sent successfully!'}), 200

    except KeyError as e:
        return jsonify({'error': 'Wrong data format: {}'.format(str(e))}), 400

if __name__ == '__main__':
    print('Server running on port 5000')
    app.run(debug=True, host='0.0.0.0', port=5000)
    
