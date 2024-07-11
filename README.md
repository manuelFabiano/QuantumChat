# PQXDH Messaging App

This project is for educational purposes, focusing on the implementation of a secure messaging app using the PQXDH protocol developed by Signal 🛡️

## 🚀 Features

- **Post-Quantum Security**: Utilizes the Kyber algorithm to ensure security against quantum computing threats.
- **End-to-End Encryption**: Ensures all messages are encrypted and only readable by the intended recipient.
- **Secure Key Exchange**: Implements a post-quantum version of the X3DH protocol.

## 🛠️ Technologies Used

- **Python** 🐍: Primary programming language for the implementation.
- **CRYSTALS-Kyber** 🔐: Post-quantum key encapsulation mechanism. (https://github.com/GiacomoPope/kyber-py)
- **Elliptic-Curve Cryptography** 🔑: Used for secure key exchanges. (https://github.com/pyca/cryptography)
- **AES-GCM** 🔒: For symmetric encryption and decryption of messages.
- **Docker** 🐳: Containerization of the server for easy deployment.

## 📝 How to Run the Server

To run the server, you'll need Docker installed on your system. Follow these steps:

1. **Navigate to the server directory**:

    ```bash
    cd server
    ```

2. **Build the Docker image**:

    ```bash
    docker compose build
    ```

3. **Run the Docker container**:

    ```bash
    docker compose up
    ```

   The server will be running on `http://localhost:5001`.

## 📧 Usage

1. **Start the server** using the steps above.
2. **Run the client**:

    Navigate to the `client` directory and execute the client script.

    ```bash
    cd client
    ./launch.sh [number of client you want to start]
    ```

3. **Start messaging**: The client application will connect to the server, allowing you to send and receive encrypted messages.

## 📚 Further Reading

- [Signal's PQXDH Protocol](https://signal.org/docs/specifications/pqxdh/)
- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
