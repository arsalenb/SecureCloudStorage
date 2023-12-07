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
#include "../Util.h"

using namespace std;

size_t calLengthLoginMessageFromTheServer()
{
    return Max_Ephemral_Public_Key_Size + sizeof(int) + Encrypted_Signature_Size + CBC_IV_Length;
}

bool receiveEphemralPublicKey(int clientSocket, EVP_PKEY *&deserializedKey, unsigned char *&serializedKey, size_t &serializedKeyLength)
{

    // Receive the certificate size
    ssize_t bytesReceived = recv(clientSocket, &serializedKeyLength, sizeof(serializedKeyLength), MSG_WAITALL);
    if (bytesReceived <= 0)
    {
        std::cerr << "Error receiving Key size" << std::endl;
        return false;
    }
    if (serializedKeyLength > Max_Ephemral_Public_Key_Size)
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

bool verifyDigitalSignature(unsigned char *data, size_t dataLength, unsigned char *signature, unsigned int signatureLength, EVP_PKEY *publicKey)
{
    const EVP_MD *md = EVP_sha256();

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        // Handle error
        return false;
    }

    int ret;
    ret = EVP_VerifyInit(ctx, md);
    if (ret == 0)
    {
        cerr << "Error: EVP_VerifyInit returned " << ret << "\n";
        return false;
    }
    ret = EVP_VerifyUpdate(ctx, data, dataLength);
    if (ret == 0)
    {
        cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n";
        return false;
    }
    ret = EVP_VerifyFinal(ctx, signature, signatureLength, publicKey);

    if (ret != 1)
    {
        cerr << "Error: Signature verification failed\n";
        return false;
    }

    EVP_MD_CTX_free(ctx);

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

bool serializeLoginMessageFromTheServer(unsigned char *serializedServerEphemralKey, int serializedServerrEphemralKeyLength,
                                        unsigned char *cipher_text, unsigned char *iv, unsigned char *&sendBuffer)
{

    // Calculate the total length of the data to be sent
    size_t totalLength = calLengthLoginMessageFromTheServer();

    // Allocate a buffer to hold the concatenated data
    sendBuffer = (unsigned char *)(malloc(totalLength));

    // Copy serializedServerKey to the buffer
    std::memcpy(sendBuffer, serializedServerEphemralKey, Max_Ephemral_Public_Key_Size);

    // Copy serializedServerKeyLength to the buffer
    std::memcpy(sendBuffer + Max_Ephemral_Public_Key_Size, &serializedServerrEphemralKeyLength, sizeof(int));

    // Copy cipher_text to the buffer
    std::memcpy(sendBuffer + Max_Ephemral_Public_Key_Size + sizeof(int), cipher_text, Encrypted_Signature_Size);

    // Copy iv to the buffer
    std::memcpy(sendBuffer + Max_Ephemral_Public_Key_Size + sizeof(int) + Encrypted_Signature_Size, iv, CBC_IV_Length);

    return true;
}

bool deserializeLoginMessageFromTheServer(unsigned char *receivedBuffer,
                                          unsigned char *&serializedServerEphemralKey, int &serializedServerrEphemralKeyLength,
                                          unsigned char *&cipher_text, unsigned char *&iv)
{

    // Allocate memory for the individual components
    serializedServerEphemralKey = (unsigned char *)(malloc(Max_Ephemral_Public_Key_Size));
    cipher_text = (unsigned char *)(malloc(Encrypted_Signature_Size));
    iv = (unsigned char *)(malloc(EVP_CIPHER_iv_length(EVP_aes_128_cbc())));

    // Copy data from the received buffer to the individual components
    std::memcpy(serializedServerEphemralKey, receivedBuffer, Max_Ephemral_Public_Key_Size);
    std::memcpy(&serializedServerrEphemralKeyLength, receivedBuffer + Max_Ephemral_Public_Key_Size, sizeof(int));
    std::memcpy(cipher_text, receivedBuffer + Max_Ephemral_Public_Key_Size + sizeof(int), Encrypted_Signature_Size);
    std::memcpy(iv, receivedBuffer + Max_Ephemral_Public_Key_Size + sizeof(int) + Encrypted_Signature_Size, CBC_IV_Length);

    return true;
}

bool loadPrivateKey(std::string privateKeyPath, EVP_PKEY *&privateKey)
{
    FILE *prvkey_file = fopen(privateKeyPath.c_str(), "r");

    if (!prvkey_file)
    {
        std::cerr << "Error: Cannot open private key file: " << privateKeyPath << "\n";
        return false;
    }

    privateKey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
    fclose(prvkey_file);

    if (!privateKey)
    {
        std::cerr << "Error: PEM_read_PrivateKey returned NULL\n";
        return false;
    }

    return true;
}