# 880II - Foundations of Cybersecurity: Secure Cloud Storage Application

This project was developed for the **Foundations of Cybersecurity** course. The goal was to implement a **secure Client–Server application** resembling a cloud storage system, where each user has dedicated private storage space on the server.  

After authentication, users can securely **upload, download, rename, and delete files** within their allocated storage. Access is restricted to each user’s own files, ensuring confidentiality and integrity.  

Three users were pre-registered on the server (`user1`, `user2`, `user3`). Each user possesses a **long-term RSA key pair**, with their private key being password-protected. The server stores usernames, RSA public keys, and allocates dedicated storage for each user.  

---

## Security Features

To meet strong security guarantees, the following protocols and cryptographic techniques were implemented:

- **Perfect Forward Secrecy (PFS)**  
  Achieved using **Elliptic-curve Diffie–Hellman (ECDH)** with the **ANSI X9.62 Prime 256v1 curve**. Temporary session keys are generated for each communication session, ensuring that compromising one session’s key does not affect past or future sessions.  

- **AES-128-CCM**  
  Used for encryption and authentication. Combines symmetric encryption with message authentication, ensuring **confidentiality** and **integrity** of transmitted data.  

- **Replay Attack Mitigation**  
  Unique counters were implemented on both server and client sides. Each encryption operation uses a unique value, preventing adversaries from reusing intercepted ciphertexts.  

- **SHA-256 Key Derivation**  
  The shared secret from ECDH is hashed using **SHA-256** to derive fixed-length session keys. This reduces the risk of cryptographic attacks and ensures robust key material.  

---

## Application Design

- **Language & Platform** – Developed in **C++17** on **Ubuntu 18.04**.  
- **Executables** – The system consists of two applications:  
  - `server` – manages users, storage, and cryptographic operations.  
  - `client` – provides the interface for user authentication and file operations.  
- **Build System** – Built using **CMake**, ensuring portability across environments.  
- **Networking Protocol** – Communication is implemented using **TCP sockets**, ensuring reliable, ordered, and error-checked data transmission.  
- **Multithreading** – Both server and client were designed in a **multi-threaded** manner to handle multiple simultaneous operations efficiently.  

---

## Project Structure

### Executables
- **Server** – Runs continuously, authenticates users, and handles secure storage operations.  
- **Client** – Connects to the server and allows the user to securely upload, download, rename, and delete files.  

### Scripts
- **Build scripts** – CMake configuration and wrappers for building executables.  
- **Testing scripts** – Automate client–server interaction testing and performance evaluation.  

---

## Compilation & Execution

### Build with CMake
```bash
mkdir build && cd build
cmake ..
make
```
###Run the Applications

Start the server:
```bash
./server
```
Connect with a client:
```bash
./client <server_address> <port>
```
