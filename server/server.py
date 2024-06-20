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

        #Check if the username is already registered
        if keys_collection.find_one({'username': username}):
            return jsonify({'error': 'Username already registered!'}), 400

        #Save user on MongoDB
        keys_collection.insert_one({
            'username': username,
            'password': password,
            "public_identity_key": public_identity_key,
            "public_prekey" : public_prekey,
            "sign_on_prekey" : sign_on_prekey,
            "public_one_time_prekeys" : public_one_time_prekeys
        })

        return jsonify({'message': 'Successly registered user!'}), 200

    except KeyError as e:
        return jsonify({'error': 'Wrong data format: {}'.format(str(e))}), 400

@app.route('/upload', methods=['POST'])
def upload_keys():
    data = request.get_json()

    try:
        #Bob's curve identity key
        identity_public_key = binascii.unhexlify(data['identity_public_key'])
        
        #Bob's signed curve prekey and its identifier
        signed_curve_prekey = binascii.unhexlify(data['signed_curve_prekey'])
        identifier_curve_prekey = data['identifier_curve_prekey']

        #Bob's signature on the curve prekey
        signature_curve_prekey = binascii.unhexlify(data['signature_curve_prekey'])

        #Bob's signed last-resort pqkem prekey and its identifier
        signed_pqkem_prekey = binascii.unhexlify(data['signed_pqkem_prekey'])
        identifier_pqkem_prekey = data['identifier_pqkem_prekey']

        #Bob's signature on the pqkem prekey
        signature_pqkem_prekey = binascii.unhexlify(data['signature_pqkem_prekey'])

        #A set of Bob's one-time curve prekeys with identifiers
        one_time_curve_prekeys = [{
            'key': binascii.unhexlify(prekey['key']),
            'id': prekey['id']
        } for prekey in data['one_time_curve_prekeys']]

        #A set of Bob's signed one-time pqkem prekeys with identifiers
        one_time_pqkem_prekeys = [{
            'key': binascii.unhexlify(prekey['key']),
            'id': prekey['id']
        } for prekey in data['one_time_pqkem_prekeys']]


        #Save keys on MongoDB
        #TODO: Da cambiare in modo che venga salvato nel documento (già esistente) dell'utente
        keys_collection.insert_one({
            'identity_public_key': identity_public_key,
            'signed_curve_prekey': signed_curve_prekey,
            'identifier_curve_prekey': identifier_curve_prekey,
            'signature_curve_prekey': signature_curve_prekey,
            'signed_pqkem_prekey': signed_pqkem_prekey,
            'identifier_pqkem_prekey': identifier_pqkem_prekey,
            'signature_pqkem_prekey': signature_pqkem_prekey,
            'one_time_curve_prekeys': one_time_curve_prekeys,
            'one_time_pqkem_prekeys': one_time_pqkem_prekeys
        })


        return jsonify({'message': 'Successly uploaded key bundle!'}), 200

    except (KeyError, binascii.Error) as e:
        return jsonify({'error': 'Wrong data format: {}'.format(str(e))}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
