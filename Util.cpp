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

bool receiveEphemralPublicKey(int clientSocket, EVP_PKEY *&deserializedKey, unsigned char *&serializedKey, int &serializedKeyLength)
{
    // Receive the certificate size

    ssize_t bytesReceived = recv(clientSocket, &serializedKeyLength, sizeof(serializedKeyLength), MSG_WAITALL);
    if (bytesReceived <= 0)
    {
        std::cerr << "Error receiving Key size" << std::endl;
        return false;
    }
    if (serializedKeyLength > Max_Public_Key_Size)
    {
        std::cerr << "Key size exceeds the max size" << std::endl;
        return false;
    }

    // Receive the key data
    serializedKey = (unsigned char *)(malloc(serializedKeyLength));
    if (!serializedKey)
    {
        fprintf(stderr, "Error allocating memory for ephemral key\n");
        return false;
    }
    bytesReceived = recv(clientSocket, serializedKey, serializedKeyLength, MSG_WAITALL);
    if (bytesReceived <= 0)
    {
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
bool generateDigitalSignature(unsigned char *data, size_t dataLength, EVP_PKEY *privateKey, unsigned char *&signature, unsigned int &signatureLength)
{
    const EVP_MD *md = EVP_sha256();

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        // Handle error
        return false;
    }

    // allocate buffer for signature:
    signature = (unsigned char *)malloc(EVP_PKEY_size(privateKey));
    if (!signature)
    {
        cerr << "Error: malloc returned NULL (signature too big?)\n";
        return false;
    }
    int ret;
    ret = EVP_SignInit(ctx, md);
    if (ret == 0)
    {
        cerr << "Error: EVP_SignInit returned " << ret << "\n";
        return false;
    }
    ret = EVP_SignUpdate(ctx, data, dataLength);
    if (ret == 0)
    {
        cerr << "Error: EVP_SignUpdate returned " << ret << "\n";
        return false;
    }
    ret = EVP_SignFinal(ctx, signature, &signatureLength, privateKey);

    if (ret == 0)
    {
        cerr << "Error: EVP_SignFinal returned " << ret << "\n";
        return false;
    }

    return true;
}
bool computeSHA256Digest(unsigned char *data, size_t dataLength, unsigned char *&digest, unsigned int &digestLength)
{
    // Create and init context
    EVP_MD_CTX *Hctx = EVP_MD_CTX_new();

    if (!Hctx)
    {
        fprintf(stderr, "Error creating EVP_MD_CTX\n");
        return false;
    }

    // Allocate memory for digest
    digest = (unsigned char *)malloc(EVP_MD_size(EVP_sha256()));

    if (!(*digest))
    {
        fprintf(stderr, "Error allocating memory for digest\n");
        EVP_MD_CTX_free(Hctx);
        return false;
    }

    // Initialize, Update (only once), and finalize digest
    if (EVP_DigestInit(Hctx, EVP_sha256()) != 1 ||
        EVP_DigestUpdate(Hctx, data, dataLength) != 1 ||
        EVP_DigestFinal(Hctx, digest, &digestLength) != 1)
    {
        fprintf(stderr, "Error computing SHA-256 digest\n");

        EVP_MD_CTX_free(Hctx);
        return false;
    }

    //  free context
    EVP_MD_CTX_free(Hctx);

    // Print digest to screen in hexadecimal
    printf("Digest is:\n");
    for (unsigned int n = 0; n < digestLength; n++)
        printf("%02x", (digest)[n]);
    printf("\n");
    return true;
}

bool serializeLoginMessageFromTheServer(unsigned char *serializedServerKey, int serializedServerKeyLength,
                                        unsigned char *cipher_text, int cipher_size, const unsigned char *iv, unsigned char *&sendBuffer)
{

    // Calculate the total length of the data to be sent
    size_t totalLength = serializedServerKeyLength + sizeof(int) + cipher_size + EVP_CIPHER_iv_length(EVP_aes_128_cbc());

    // Allocate a buffer to hold the concatenated data
    sendBuffer = (unsigned char *)(malloc(totalLength));

    // Copy serializedServerKey to the buffer
    std::memcpy(sendBuffer, serializedServerKey, serializedServerKeyLength);

    // Copy serializedServerKeyLength to the buffer
    std::memcpy(sendBuffer + serializedServerKeyLength, &serializedServerKeyLength, sizeof(int));

    // Copy cipher_text to the buffer
    std::memcpy(sendBuffer + serializedServerKeyLength + sizeof(int), cipher_text, cipher_size);

    // Copy iv to the buffer
    std::memcpy(sendBuffer + serializedServerKeyLength + sizeof(int) + cipher_size, iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));

    return true;
}
