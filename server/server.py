from flask import Flask, request, jsonify
from pymongo import MongoClient
import binascii
import os

app = Flask(__name__)

# MongoDB connection
mongo_host = os.getenv('MONGO_HOST', 'localhost')
mongo_port = int(os.getenv('MONGO_PORT', '27017'))
mongo_client = MongoClient(mongo_host, mongo_port)
db = mongo_client.db
keys_collection = db.keys


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    try:
        username = data['username']
        password = data['password']
        public_identity_key= data["public_keys"]["public_identity_key"]
        public_prekey= data["public_keys"]["public_prekey"]
        sign_on_prekey= data["public_keys"]["sign_on_prekey"]
        public_one_time_prekeys= data["public_keys"]["public_one_time_prekeys"]
        public_last_resort_pqkem_key = data["public_keys"]["public_last_resort_pqkem_key"]
        sign_on_last_resort_pqkem_key = data["public_keys"]["sign_on_last_resort_pqkem_key"]
        public_one_time_pqkem_prekeys = data["public_keys"]["public_one_time_pqkem_prekeys"]
        sign_on_one_time_pqkem_prekeys = data["public_keys"]["sign_on_one_time_pqkem_prekeys"]

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
                "sign_on_prekey" : sign_on_prekey,
                "public_one_time_prekeys" : public_one_time_prekeys,
                "public_last_resort_pqkem_key" : public_last_resort_pqkem_key,
                "sign_on_last_resort_pqkem_key" : sign_on_last_resort_pqkem_key,
                "public_one_time_pqkem_prekeys" : public_one_time_pqkem_prekeys,
                "sign_on_one_time_pqkem_prekeys" : sign_on_one_time_pqkem_prekeys
            }
        })

        return jsonify({'message': 'Successfully registered user!'}), 200

    except KeyError as e:
        return jsonify({'error': 'Wrong data format: {}'.format(str(e))}), 400


if __name__ == '__main__':
    print('Server running on port 5000')
    app.run(debug=True, host='0.0.0.0', port=5000)
    
