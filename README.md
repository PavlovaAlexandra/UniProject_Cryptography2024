# UniProject Cryptography 2024

## Project Description
This project is an implementation of secure client-server communication using cryptographic techniques. It utilizes RSA for key exchange, AES for message encryption, and hashing for data integrity verification. Additionally, the client generates a One-Time Password (OTP) for authentication, and the server integrates an SQLite database for logging and user management.

## Features Implemented
- **RSA Key Exchange**: Secure key exchange between client and server.
- **AES Encryption**: Encryption and decryption of messages using AES.
- **Hashing**: Hashing mechanisms for data integrity verification.
- **Client-Server Architecture**: A basic client-server communication model.
- **One-Time Password (OTP)**: The client generates an OTP for authentication.
- **SQLite Database**: The server utilizes SQLite for storing user data and logs.

## Project Structure
- `server.cpp` - The server-side implementation that handles encrypted communication and database operations.
- `client.cpp` - The client-side implementation that connects to the server, generates OTPs, and communicates securely.
- `encryptionAES.cpp/.h` - AES encryption and decryption functions.
- `RSA_utils.cpp/.h` - RSA key generation and encryption utilities.
- `hashing.cpp/.h` - Hashing functions for data integrity.
- `Makefile` - Compilation instructions.

## How to Build and Run
### Prerequisites
Ensure you have the following installed:
- A C++ compiler (GCC recommended)
- `make`
- `sqlite3` library (for database support)

### Compilation
Run the following command to build the project:
```sh
make
```
This will generate the `server` and `client` executables.

### Running the Server
In the first terminal, start the server:
```sh
./server
```
The server will initialize an SQLite database and wait for client connections.

### Running the Client
In the second terminal, start the client:
```sh
./client
```
The client will connect to the server, generate an OTP for authentication, establish a secure channel using RSA key exchange, and communicate using AES-encrypted messages.

## Notes
- Ensure that both the client and server run on the same network.
- Modify the IP address in `client.cpp` if running on a different machine.
- The server logs user activity in an SQLite database.
- You can enhance the project by adding authentication mechanisms or a GUI for better usability.
