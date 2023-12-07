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
#include "../crypto.h"

using namespace std;
const int PORT = 8080;
const int BUFFER_SIZE = 4096;
const int MAX_USERNAME_LENGTH = 5;

// Function to handle each connected client
int handleClient(int clientSocket, const std::vector<std::string> &userNames)
{
    unsigned char buffer[MAX_USERNAME_LENGTH + 1] = {0}; // +1 for null terminator
    ssize_t bytesRead = recv(clientSocket, buffer, MAX_USERNAME_LENGTH, MSG_WAITALL);

    if (bytesRead <= 0)
    {
        std::cerr << "Error receiving username from client" << std::endl;
        close(clientSocket);
        return 0;
    }

    std::string receivedUserName((const char *)buffer);
    std::cout << "Received username from client: " << receivedUserName << std::endl;

    // Check if username exists
    bool usernameExists = false;
    for (const auto &user : userNames)
    {
        if (user == receivedUserName)
        {
            usernameExists = true;
            break;
        }
    }
    // Send result back to client
    std::string resultMsg = (usernameExists) ? "1" : "0";
    send(clientSocket, resultMsg.c_str(), resultMsg.size(), 0);

    if (usernameExists)
    {
        // Load the server certificate from PEM file
        FILE *server_certificate_file = fopen("Cloud Strorage Server_cert.pem", "r");
        if (!server_certificate_file)
        {
            std::cerr << "Error loading server certificate" << std::endl;
            std::cout.flush();
            close(clientSocket);
            return 0;
        }

        X509 *serverCert = PEM_read_X509(server_certificate_file, NULL, NULL, NULL);
        fclose(server_certificate_file);

        if (!serverCert)
        {
            std::cerr << "Error reading server certificate" << std::endl;
            std::cout.flush();
            close(clientSocket);
            return 0;
        }

        // Send server certificate to client
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio)
        {
            std::cerr << "Error creating BIO" << std::endl;
            std::cout.flush();
            X509_free(serverCert);
            close(clientSocket);
            return 0;
        }

        int result = PEM_write_bio_X509(bio, serverCert);

        if (!result)
        {
            std::cerr << "[-] (CertificateStore) Failed to write the certificate in the BIO" << endl;
            std::cerr.flush();
            std::cout.flush();
            BIO_free(bio);
            return 0;
        }

        // trucate to the size of the certificate
        unsigned char certBuffer[BUFFER_SIZE] = {0};
        int certSize = BIO_read(bio, certBuffer, sizeof(certBuffer));
        if (certSize <= 0)
            return 0;
        BIO_free(bio);

        std::cout << "size of certificate " << certSize << std::endl;

        // Send the certificate size to the client
        send(clientSocket, &certSize, sizeof(certSize), 0);

        // Send the certificate data to the client
        send(clientSocket, certBuffer, certSize, 0);

        // receive the client ECDH public key
        EVP_PKEY *deserializedClientKey;
        unsigned char *sClientKey;
        size_t sClientKeyLength;

        if (!receiveEphemralPublicKey(clientSocket, deserializedClientKey, sClientKey, sClientKeyLength))
        {

            // Handle the case where receiving or deserialization failed
            std::cerr << "Failed to receive or deserialize the key" << std::endl;
            return 0;
        }

        // Generate the elliptic curve diffie-Hellman keys for the client
        EVP_PKEY *ECDH_Keys;
        if (!(ECDH_Keys = ECDHKeyGeneration()))
        {
            cerr << "[SERVER] ECDH key generation failed" << endl;
            return 0;
        }

        // serialize the public key

        unsigned char *sServerKey;
        size_t sServerKeyLength;

        if (!serializePubKey(ECDH_Keys, sServerKey, sServerKeyLength))
        {
            cerr << "[SERVER] Serialization of public key failed" << endl;
            return 0;
        }

        // calculate (g^a)^b
        unsigned char *sharedSecretKey;
        size_t sharedSecretLength;
        int derivationResult = deriveSharedSecret(ECDH_Keys, deserializedClientKey, sharedSecretKey, sharedSecretLength);

        if (derivationResult == -1)
        {
            return 0;
        }
        // generate session key Sha256((g^a)^b)
        unsigned char *digest;
        unsigned int digestlen;

        if (!computeSHA256Digest(sharedSecretKey, sharedSecretLength, digest, digestlen))
        {
            cerr << "[SERVER] Shared secret derivation failed" << endl;
            return 0;
        }
        // take first 128 of the the digest
        const EVP_CIPHER *cipher = EVP_aes_128_cbc();

        int sessionKeyLength = EVP_CIPHER_key_length(cipher);
        unsigned char *sessionKey = (unsigned char *)malloc(sessionKeyLength);
        memcpy(sessionKey, digest, sessionKeyLength);

        printf("Session key is:\n");
        for (unsigned int n = 0; n < sessionKeyLength; n++)
            printf("%02x", (sessionKey)[n]);
        printf("\n");
// Free the shared secret buffer!
#pragma optimize("", off)
        memset(digest, 0, digestlen);
        memset(sharedSecretKey, 0, sharedSecretLength);
#pragma optimize("", on)
        free(digest);
        free(sharedSecretKey);

        // concatinate (g^b,g^a)
        // Concatenate the serialized keys
        unsigned char *concatenatedKeys = nullptr;
        int concatenatedkeysLength = sServerKeyLength + sClientKeyLength;
        concatenateKeys(sServerKeyLength, sClientKeyLength,
                        sServerKey, sClientKey, concatenatedKeys, concatenatedkeysLength);

        printf("concatennated keys :\n%s\n", concatenatedKeys);
        // Now concatenatedKeys contains the serialized form of both keys

        // read server private key
        // load server private key:
        EVP_PKEY *prvkey = nullptr;
        if (!loadPrivateKey("server_private_key.pem", prvkey))
        {
            return 0;
        }

        // create the digiatl signature <(g^a,g^b)>s using the server private key
        unsigned char *signature;
        unsigned int signatureLength;
        if (!generateDigitalSignature(concatenatedKeys, concatenatedkeysLength, prvkey, signature, signatureLength))
        {
            return 0;
        }
        EVP_PKEY_free(prvkey);
        // Signature generation successful, print the signature
        cout << "Digital Signature:" << endl;
        BIO_dump_fp(stdout, (const char *)signature, signatureLength);

        // encrypt  {<(g^a,g^b)>s}k  using the session key
        unsigned char *cipher_text;
        int cipher_size;
        unsigned char *iv;

        if (!encryptTextAES(signature, signatureLength, sessionKey, cipher_text, cipher_size, iv))
        {
            return 0;
        }

        // send to the client: (g^b) ,(g^b) size, {<(g^a,g^b)>s}k, IV

        unsigned char *sendBuffer = nullptr;
        if (!serializeLoginMessageFromTheServer(sServerKey, sServerKeyLength,
                                                cipher_text, iv, sendBuffer))
        {
            return 0;
        }
        int sendBufferSize = calLengthLoginMessageFromTheServer();
        send(clientSocket, sendBuffer, sendBufferSize, 0);

        free(cipher_text);

        // free memory
        delete[] sClientKey;
        delete[] sServerKey;
        delete[] concatenatedKeys;
        // Clean up
        X509_free(serverCert);
        EVP_PKEY_free(deserializedClientKey);
    }
    else
    {
        // If username does not exist
    }

    // Close client socket
    close(clientSocket);
}

int main()
{
    // Create socket
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1)
    {
        std::cerr << "Error creating server socket" << std::endl;
        return -1;
    }

    // Bind socket to port
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
        std::cerr << "Error binding socket to port" << std::endl;
        close(serverSocket);
        return -1;
    }

    // Listen for connections
    if (listen(serverSocket, 5) == -1)
    {
        std::cerr << "Error listening for connections" << std::endl;
        close(serverSocket);
        return -1;
    }

    std::cout << "Server listening on port " << PORT << "..." << std::endl;

    // List of usernames
    std::vector<std::string> userNames = {"user1", "user2", "user3"};

    while (true)
    {
        // Accept connection
        sockaddr_in clientAddr{};
        socklen_t clientAddrLen = sizeof(clientAddr);
        int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &clientAddrLen);
        if (clientSocket == -1)
        {
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
