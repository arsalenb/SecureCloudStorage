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
    char buffer[MAX_USERNAME_LENGTH+1] = {0}; // +1 for null terminator  
    ssize_t bytesRead = recv(clientSocket, buffer, MAX_USERNAME_LENGTH, MSG_WAITALL);

    if (bytesRead <= 0) {
        std::cerr << "Error receiving username from client" << std::endl;
        close(clientSocket);
        return;
    }

    std::string receivedUserName(buffer);
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
        char certBuffer[BUFFER_SIZE]={0};
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
         EVP_PKEY* receivedKey = nullptr;

    if (receiveEphemralPublicKey(clientSocket, receivedKey)) {
        // Successfully received and deserialized the key

        // Use the receivedKey as needed

        // Don't forget to free the deserialized key when done
        EVP_PKEY_free(receivedKey);
    } else {
        // Handle the case where receiving or deserialization failed
        std::cerr << "Failed to receive or deserialize the key" << std::endl;
        return;
    }

        // Clean up
        X509_free(serverCert);
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


