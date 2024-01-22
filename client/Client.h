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

typedef std::vector<unsigned char> Buffer;

class Client
{
private:
    std::string username;
    std::string password;
    int communcation_socket;
    Buffer session_key;
    int s_counter = 0;
    int r_counter = 0;

public:
    Client();
    int login();
    int handleMenuChoice(const std::string &choice);

    bool receiveServerCertificate(X509 *&serverCert);
    bool verifyServerCertificate(X509 *caCert, X509_CRL *crl, X509 *serverCert);

    // --------- Application Routines ---------
    int upload_file();
    int download_file();
    int list_files();
    int rename_file();
    int delete_file();
    int logout();
    // ----------------------------------------

    // Start client application
    int start();

    ~Client();
};

#endif
