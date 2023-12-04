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

bool receiveEphemralPublicKey(int clientSocket, EVP_PKEY*& deserializedKey, unsigned char*& serializedKey,int& serializedKeyLength) {
    // Receive the certificate size
    
    ssize_t bytesReceived = recv(clientSocket, &serializedKeyLength, sizeof(serializedKeyLength), MSG_WAITALL);
    if (bytesReceived <= 0) {
        std::cerr << "Error receiving Key size" << std::endl;
        return false;
    }
    if(serializedKeyLength>Max_Public_Key_Size)
    {
        std::cerr << "Key size exceeds the max size" << std::endl;
        return false;
    }

    // Receive the key data
     serializedKey = (unsigned char *)(malloc(serializedKeyLength));
    if (!serializedKey) {
        fprintf(stderr, "Error allocating memory for ephemral key\n");
        return false;
    }
    bytesReceived = recv(clientSocket, serializedKey, serializedKeyLength, MSG_WAITALL);
    if (bytesReceived <= 0) {
        std::cerr << "Error receiving key data" << std::endl;
        return false;
    }
    deserializedKey = deserializePublicKey(serializedKey, serializedKeyLength);
    if (deserializedKey == NULL)
    {
        std::cerr << "Error receiving serializing data" << std::endl;
        return false;
    }
    return true;
}


// Function to perform digital signature
bool generateDigitalSignature( unsigned char* data, size_t dataLength, EVP_PKEY* privateKey, unsigned char*& signature, unsigned int& signatureLength) {
    const EVP_MD* md = EVP_sha256();

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        // Handle error
        return false;
    }

    // allocate buffer for signature:
     signature = (unsigned char*)malloc(EVP_PKEY_size(privateKey));
     if(!signature) { 
        cerr << "Error: malloc returned NULL (signature too big?)\n";
        return false;
         }
    int ret;
    ret = EVP_SignInit(ctx, md);
   if(ret == 0){ 
    cerr << "Error: EVP_SignInit returned " << ret << "\n";
     return false; 
    }
   ret = EVP_SignUpdate(ctx, data, dataLength);
   if(ret == 0){ 
    cerr << "Error: EVP_SignUpdate returned " << ret << "\n"; 
   return false; 
     }
   
   ret = EVP_SignFinal(ctx, signature, &signatureLength, privateKey);
   if(ret == 0){ 
    cerr << "Error: EVP_SignFinal returned " << ret << "\n"; 
    return false; 
    }

   
    return true;
}
