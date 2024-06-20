import requests
from cryptography.hazmat.primitives import hashes

#Server URL
SERVER = "http://172.21.0.5:5000"

def register(username, password):
    url = SERVER + "/register"
    payload = {
        "username": username,
        "password": password
    }
    response = requests.post(url, json=payload)
    return response

def main():
    print("Welcome to QuantumChat!")
        
    #TODO: Controllare se l'utente è già registrato o meno

    username = input("Enter your username: ")
    password = input("Enter your password: ")

    #Hash the password
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password.encode())
    password = digest.finalize()

    print(type(password))
    #Register the user
    response = register(username, str(password))

    print(response)


if __name__ == "__main__":
    main()