// client.h
#ifndef CLIENT_H
#define CLIENT_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

const int PORT = 8080;
const int MAX_CERTIFICATE_SIZE = 4096;
const int MAX_USERNAME_LENGTH = 5;

class Client
{
private:
    int clientSocket;
    std::string username;

    // Add other private members as needed

public:
    Client();

    bool connectToServer();

    bool sendUsername();

    bool receiveServerResponse();

    bool receiveServerCertificate(X509 *&serverCert);

    bool verifyServerCertificate(X509 *caCert, X509_CRL *crl, X509 *serverCert);
    void performClientJob();

    // Add other public member functions as needed

    ~Client();
};

#endif // CLIENT_H
