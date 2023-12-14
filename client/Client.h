#ifndef CLIENT_H
#define CLIENT_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>
#include <vector>

const int PORT = 8080;
const int MAX_CERTIFICATE_SIZE = 4096;
const int MAX_USERNAME_LENGTH = 5;

typedef std::vector<unsigned char> Buffer;

class Client
{
private:
    std::string username;
    int clientSocket;
    int send_counter = 0;
    int rcv_counter = 0;

public:
    Client();

    bool connectToServer();

    bool sendUsername();

    bool receiveServerResponse();

    bool receiveServerCertificate(X509 *&serverCert);

    bool verifyServerCertificate(X509 *caCert, X509_CRL *crl, X509 *serverCert);

    void performClientJob();

    int upload_file();

    ~Client();
};

#endif
