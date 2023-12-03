#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>

#include <vector>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "Diffie-Hellman.h"

using namespace std;
const int Max_Public_Key_Size = 2048;

bool receiveEphemralPublicKey(int clientSocket, EVP_PKEY*& deserializedKey) {
    // Receive the certificate size
    int keyLength;
    ssize_t bytesReceived = recv(clientSocket, &keyLength, sizeof(keyLength), MSG_WAITALL);
    if (bytesReceived <= 0) {
        std::cerr << "Error receiving Key size" << std::endl;
        return false;
    }
    if(keyLength>Max_Public_Key_Size)
    {
        std::cerr << "Key size exceeds the max size" << std::endl;
        return false;
    }

    // Receive the key data
    char keyBuffer[keyLength]={0};
    bytesReceived = recv(clientSocket, keyBuffer, keyLength, MSG_WAITALL);
    if (bytesReceived <= 0) {
        std::cerr << "Error receiving key data" << std::endl;
        return false;
    }
    deserializedKey = deserializePublicKey(keyBuffer, keyLength);
    if (deserializedKey == NULL)
    {
        std::cerr << "Error receiving serializing data" << std::endl;
        return false;
    }
    return true;
}
