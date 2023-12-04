#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <vector>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../Util.h"
using namespace std;
const int PORT = 8080;
const int BUFFER_SIZE = 4096;
const int MAX_USERNAME_LENGTH = 5;



// Function to handle each connected client
void handleClient(int clientSocket, const std::vector<std::string>& userNames) {
   unsigned char buffer[MAX_USERNAME_LENGTH+1] = {0}; // +1 for null terminator  
    ssize_t bytesRead = recv(clientSocket, buffer, MAX_USERNAME_LENGTH, MSG_WAITALL);

    if (bytesRead <= 0) {
        std::cerr << "Error receiving username from client" << std::endl;
        close(clientSocket);
        return;
    }

    std::string receivedUserName((const char *)buffer);
    std::cout << "Received username from client: " << receivedUserName << std::endl;

    // Check if username exists
    bool usernameExists = false;
    for (const auto& user : userNames) {
        if (user == receivedUserName) {
            usernameExists = true;
            break;
        }
    }
    // Send result back to client
    std::string resultMsg = (usernameExists) ? "1" : "0";
    send(clientSocket, resultMsg.c_str(), resultMsg.size(), 0);

    if (usernameExists) {
        // Load the server certificate from PEM file
         FILE* server_certificate_file = fopen("Cloud Strorage Server_cert.pem", "r");
        if (!server_certificate_file) {
            std::cerr << "Error loading server certificate" << std::endl;
             std::cout.flush();
            close(clientSocket);
            return;
        }

        X509* serverCert = PEM_read_X509(server_certificate_file, NULL, NULL, NULL);
        fclose(server_certificate_file);

        if (!serverCert) {
            std::cerr << "Error reading server certificate" << std::endl;
             std::cout.flush();
            close(clientSocket);
            return;
        }

        // Send server certificate to client
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            std::cerr << "Error creating BIO" << std::endl;
             std::cout.flush();
            X509_free(serverCert);
            close(clientSocket);
            return;
        }
         

        int result=PEM_write_bio_X509(bio, serverCert);

        if (!result) {
        std::cerr << "[-] (CertificateStore) Failed to write the certificate in the BIO" << endl; 
          std::cerr.flush();
           std::cout.flush();
        BIO_free(bio);
        return ;
    }

    // trucate to the size of the certificate
       unsigned char certBuffer[BUFFER_SIZE]={0};
        int certSize = BIO_read(bio, certBuffer, sizeof(certBuffer));
        if(certSize <= 0)
		return;
        BIO_free(bio);

       std::cout << "size of certificate " +certSize;
        std::cout.flush();
        // Send the certificate size to the client
        send(clientSocket, &certSize, sizeof(certSize), 0);

        // Send the certificate data to the client
        send(clientSocket, certBuffer, certSize, 0);

        // receive the client DH public key 
         EVP_PKEY* deserializedClientKey = nullptr;
         unsigned char *serializedClienKey;
         int serializedClientKeyLength;

    if (!receiveEphemralPublicKey(clientSocket, deserializedClientKey,serializedClienKey,serializedClientKeyLength)) {
    
        // Handle the case where receiving or deserialization failed
        std::cerr << "Failed to receive or deserialize the key" << std::endl;
        return;
    }
       printf("serialized client Key :\n%s\n", serializedClienKey);
    // generate the diffie-Hellman keys for the server
        EVP_PKEY *DH_Keys = diffieHellmanKeyGeneration();
        int len_serialized_public_key = 0;
        // serialize the public key
        int serializedServerKeyLength;
        unsigned char* serializedServerKey = serializePublicKey(DH_Keys, &serializedServerKeyLength);

        if (serializedServerKey == NULL) {
              std::cerr << "Failed to serialize the key" << std::endl;
            return;
        }
        unsigned char *skey;
        size_t skeylen;
        int  derivationResult = derive_shared_secret(DH_Keys, deserializedClientKey, skey, skeylen);
       
        if(derivationResult==-1)
        {
            return;
        }
        // concatinate (g^a,g^b)
        // Concatenate the serialized keys
        int concatenatedkeysLength=serializedServerKeyLength + serializedClientKeyLength;
        unsigned char* concatenatedKeys = new unsigned char[concatenatedkeysLength];
        memcpy(concatenatedKeys, serializedServerKey, serializedServerKeyLength);
        memcpy(concatenatedKeys + serializedServerKeyLength,serializedClienKey , serializedClientKeyLength);


          printf("concatennated keys :\n%s\n", concatenatedKeys);
        // Now concatenatedKeys contains the serialized form of both keys

        // read server private key
        // load server private key:
        FILE* prvkey_file = fopen("server_private_key.pem", "r");

        if(!prvkey_file){
             cerr << "Error: cannot open server key file" ;
             return;
             }

        EVP_PKEY* prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
        fclose(prvkey_file);

        if(!prvkey){ 
            cerr << "Error: PEM_read_PrivateKey returned NULL\n";
             return;
             }

            // create the digiatl signature
             unsigned char* signature;
            unsigned int signatureLength;
             if (!generateDigitalSignature(concatenatedKeys, concatenatedkeysLength, prvkey, signature, signatureLength)) {
                return;
            } 
             EVP_PKEY_free(prvkey);


              printf("signature  :\n%s\n", signature);
              



        

        // Don't forget to free memory
        delete[] serializedClienKey;
        delete[] serializedServerKey;
        delete[] concatenatedKeys;
        // Clean up
        X509_free(serverCert);
        EVP_PKEY_free(deserializedClientKey);
    } else {
        // If username does not exist
      
       
    }
       
    // Close client socket
    close(clientSocket);
}


int main() {
    // Create socket
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        std::cerr << "Error creating server socket" << std::endl;
        return -1;
    }

    // Bind socket to port
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        std::cerr << "Error binding socket to port" << std::endl;
        close(serverSocket);
        return -1;
    }

    // Listen for connections
    if (listen(serverSocket, 5) == -1) {
        std::cerr << "Error listening for connections" << std::endl;
        close(serverSocket);
        return -1;
    }

    std::cout << "Server listening on port " << PORT << "..." << std::endl;

    // List of usernames
    std::vector<std::string> userNames = {"user1", "user2", "user3"};

    while (true) {
        // Accept connection
        sockaddr_in clientAddr{};
        socklen_t clientAddrLen = sizeof(clientAddr);
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket == -1) {
            std::cerr << "Error accepting connection" << std::endl;
            continue;
        }

        // Create a new thread for each connected client
        std::thread t1(&handleClient, clientSocket, std::cref(userNames));
       t1.detach();

        
    }

    // Close server socket (This part will never be reached in this example)
    close(serverSocket);

    return 0;
}


