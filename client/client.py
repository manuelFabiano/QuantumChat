import requests

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


print("Welcome to QuantumChat!")
    
#TODO: Controllare se l'utente è già registrato o meno

username = input("Enter your username: ")
password = input("Enter your password: ")

response = register(username, password)

print(response)


