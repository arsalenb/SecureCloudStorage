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
#include "./Diffie-Hellman.h"
#include "./Util.h"
#include <limits>
#include <openssl/rand.h>

using namespace std;

size_t calLengthLoginMessageFromTheServer()
{
    return Max_Ephemral_Public_Key_Size + sizeof(int) + Encrypted_Signature_Size + CBC_IV_Length;
}

bool receiveEphemeralPublicKey(int clientSocket, EVP_PKEY *&deserializedKey, std::vector<unsigned char> &serializedKey)
{

    // Receive the certificate size
    size_t serializedKeyLength;

    if (!receiveNumber(clientSocket, serializedKeyLength))
    {
        std::cerr << "Error receiving Key size" << std::endl;
        return false;
    }
    if (serializedKeyLength > Max_Ephemral_Public_Key_Size)
    {
        std::cerr << "Key size exceeds the max size" << std::endl;
        return false;
    }
    serializedKey.resize(serializedKeyLength);
    cout << serializedKey.size();
    if (!receiveData(clientSocket, serializedKey, serializedKeyLength))
    {
        std::cerr << "Error receiving key data" << std::endl;
        return false;
    }
    deserializedKey = deserializePublicKey(serializedKey);
    if (deserializedKey == NULL)
    {
        std::cerr << "Error receiving serializing data" << std::endl;
        return false;
    }
    return true;
}

// Function to perform digital signature
bool generateDigitalSignature(std::vector<unsigned char> &data, EVP_PKEY *privateKey, std::vector<unsigned char> &signature)
{
    const EVP_MD *md = EVP_sha256();
    size_t dataLength = data.size();
    unsigned int signatureLength;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        // Handle error
        return false;
    }

    // Initialize signature vector with the expected size
    signature.resize(EVP_PKEY_size(privateKey));
    int ret;
    ret = EVP_SignInit(ctx, md);
    if (ret == 0)
    {
        cerr << "Error: EVP_SignInit returned " << ret << "\n";
        EVP_MD_CTX_free(ctx);
        return false;
    }
    ret = EVP_SignUpdate(ctx, data.data(), dataLength);
    if (ret == 0)
    {
        cerr << "Error: EVP_SignUpdate returned " << ret << "\n";
        EVP_MD_CTX_free(ctx);
        return false;
    }
    ret = EVP_SignFinal(ctx, signature.data(), &signatureLength, privateKey);

    if (ret == 0)
    {
        cerr << "Error: EVP_SignFinal returned " << ret << "\n";
        EVP_MD_CTX_free(ctx);
        return false;
    }

    return true;
}

bool verifyDigitalSignature(vector<unsigned char> &data, vector<unsigned char> &signature, EVP_PKEY *publicKey)
{
    const EVP_MD *md = EVP_sha256();
    unsigned int signatureLength;

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
    ret = EVP_VerifyUpdate(ctx, data.data(), data.size());
    if (ret == 0)
    {
        cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n";
        return false;
    }
    ret = EVP_VerifyFinal(ctx, signature.data(), signature.size(), publicKey);

    if (ret != 1)
    {
        cerr << "Error: Signature verification failed\n";
        return false;
    }

    EVP_MD_CTX_free(ctx);

    return true;
}

bool computeSHA256Digest(std::vector<unsigned char> &data, std::vector<unsigned char> &digest)
{
    size_t dataLength = data.size();
    unsigned int digestLength;
    // Create and init context
    EVP_MD_CTX *Hctx = EVP_MD_CTX_new();

    if (!Hctx)
    {
        fprintf(stderr, "Error creating EVP_MD_CTX\n");
        return false;
    }
    digest.resize(EVP_MD_size(EVP_sha256()));

    // Initialize, Update (only once), and finalize digest
    if (EVP_DigestInit(Hctx, EVP_sha256()) != 1 ||
        EVP_DigestUpdate(Hctx, data.data(), dataLength) != 1 ||
        EVP_DigestFinal(Hctx, digest.data(), &digestLength) != 1)
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

bool serializeLoginMessageFromTheServer(vector<unsigned char> &serializedServerEphemralKey,
                                        vector<unsigned char> &cipher_text, vector<unsigned char> &iv, vector<unsigned char> &sendBuffer)
{
    int serializedServerrEphemralKeyLength = serializedServerEphemralKey.size();

    // Calculate the total length of the data to be sent
    size_t totalLength = calLengthLoginMessageFromTheServer();

    // Resize the sendBuffer to hold the concatenated data
    sendBuffer.resize(totalLength);

    // Copy serializedServerKey to the buffer
    std::memcpy(sendBuffer.data(), serializedServerEphemralKey.data(), Max_Ephemral_Public_Key_Size);

    // Copy serializedServerKeyLength to the buffer
    std::memcpy(sendBuffer.data() + Max_Ephemral_Public_Key_Size, &serializedServerrEphemralKeyLength, sizeof(int));

    // Copy cipher_text to the buffer
    std::memcpy(sendBuffer.data() + Max_Ephemral_Public_Key_Size + sizeof(int), cipher_text.data(), Encrypted_Signature_Size);

    // Copy iv to the buffer
    std::memcpy(sendBuffer.data() + Max_Ephemral_Public_Key_Size + sizeof(int) + Encrypted_Signature_Size, iv.data(), CBC_IV_Length);

    return true;
}

bool deserializeLoginMessageFromTheServer(vector<unsigned char> &receivedBuffer,
                                          vector<unsigned char> &serializedServerEphemralKey,
                                          vector<unsigned char> &cipher_text, vector<unsigned char> &iv)
{

    // Allocate memory for the individual components
    std::vector<unsigned char> maxSerializedServerEphemralKey(Max_Ephemral_Public_Key_Size);

    cipher_text.resize(Encrypted_Signature_Size);
    iv.resize(CBC_IV_Length);

    // Copy data from the received buffer to the individual components
    std::memcpy(maxSerializedServerEphemralKey.data(), receivedBuffer.data(), Max_Ephemral_Public_Key_Size);

    int serializedServerrEphemralKeyLength;
    std::memcpy(&serializedServerrEphemralKeyLength, receivedBuffer.data() + Max_Ephemral_Public_Key_Size, sizeof(int));

    std::memcpy(cipher_text.data(), receivedBuffer.data() + Max_Ephemral_Public_Key_Size + sizeof(int), Encrypted_Signature_Size);
    std::memcpy(iv.data(), receivedBuffer.data() + Max_Ephemral_Public_Key_Size + sizeof(int) + Encrypted_Signature_Size, CBC_IV_Length);

    // copy portion to the serialized ephemral key
    // Create a new vector with the specified length and copy the data

    serializedServerEphemralKey.insert(serializedServerEphemralKey.begin(), maxSerializedServerEphemralKey.begin(),
                                       maxSerializedServerEphemralKey.begin() + serializedServerrEphemralKeyLength);

    return true;
}

bool serializeLoginMessageFromTheClient(vector<unsigned char> &cipher_text, vector<unsigned char> &iv, vector<unsigned char> &sendBuffer)
{
    // Calculate the total length of the data to be sent
    size_t totalLength = Encrypted_Signature_Size + CBC_IV_Length;

    // Resize the sendBuffer to hold the concatenated data
    sendBuffer.resize(totalLength);

    // Copy cipher_text to the buffer
    std::memcpy(sendBuffer.data(), cipher_text.data(), Encrypted_Signature_Size);

    // Copy iv to the buffer
    std::memcpy(sendBuffer.data() + Encrypted_Signature_Size, iv.data(), CBC_IV_Length);

    return true;
}

bool deserializeLoginMessageFromTheClient(vector<unsigned char> &receivedBuffer,
                                          vector<unsigned char> &cipher_text, vector<unsigned char> &iv)
{

    // Resize cipher_text and iv vectors to hold the deserialized data
    cipher_text.resize(Encrypted_Signature_Size);
    iv.resize(CBC_IV_Length);

    // Copy cipher_text from the buffer
    std::memcpy(cipher_text.data(), receivedBuffer.data(), Encrypted_Signature_Size);

    // Copy iv from the buffer
    std::memcpy(iv.data(), receivedBuffer.data() + Encrypted_Signature_Size, CBC_IV_Length);

    return true;
}

bool loadPrivateKey(std::string privateKeyPath, EVP_PKEY *&privateKey, string pem_pass)
{
    FILE *prvkey_file = fopen(privateKeyPath.c_str(), "r");

    if (!prvkey_file)
    {
        std::cerr << "Error: Cannot open private key file: " << privateKeyPath << "\n";
        return false;
    }

    privateKey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, (void *)pem_pass.c_str());
    fclose(prvkey_file);

    if (!privateKey)
    {
        std::cerr << "Error: PEM_read_PrivateKey returned NULL\n";
        return false;
    }

    return true;
}

bool loadPublicKey(const std::string publicKeyPath, EVP_PKEY *&publicKey)
{
    FILE *file = fopen(publicKeyPath.c_str(), "r");
    if (!file)
    {
        fprintf(stderr, "Error opening file: %s\n", publicKeyPath.c_str());
        return false;
    }

    publicKey = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);

    fclose(file);

    if (!publicKey)
    {
        fprintf(stderr, "Error reading public key from PEM file\n");
        return false;
    }

    return true;
}

bool receiveData(int socket, std::vector<unsigned char> &buffer, size_t bufferSize)
{
    try
    {
        ssize_t bytesRead = recv(socket, buffer.data(), bufferSize, MSG_WAITALL);

        if (bytesRead <= 0)
        {
            std::cerr << "Error receiving data " << std::endl;
            return false;
        }

        return true;
    }

    catch (const std::exception &e)
    {
        // Catch the exception and handle it
        std::cerr << "Exception: " << e.what() << std::endl;
        return false;
    }
}

bool sendData(int socket, std::vector<unsigned char> &data)
{

    try
    {
        ssize_t bytesSent = send(socket, data.data(), data.size(), MSG_NOSIGNAL);

        if (bytesSent == -1)
        {

            if (errno == EPIPE)
            {
                std::cerr << "Error sending data due to a connection issue" << std::endl;

                return false;
            }
            std::cerr << "Error sending data " << std::endl;

            return false;
        }

        return true;
    }
    catch (const std::exception &e)
    {
        // Catch the exception and handle it
        std::cerr << "Exception: " << e.what() << std::endl;
        return false;
    }
}

bool receiveNumber(int socket, size_t &number)
{

    try
    {
        ssize_t bytesReceived = recv(socket, &number, sizeof(number), MSG_WAITALL);

        if (bytesReceived <= 0)
        {
            std::cerr << "Error receiving the number " << std::endl;
            return false;
        }
        return true;
    }

    catch (const std::exception &e)
    {
        // Catch the exception and handle it
        std::cerr << "Exception: " << e.what() << std::endl;
        return false;
    }
}

bool sendNumber(int socket, size_t number)
{
    try
    {
        ssize_t bytesSent = send(socket, &number, sizeof(number), MSG_NOSIGNAL);

               if (bytesSent != sizeof(number) || bytesSent == -1)
        {

            if (errno == EPIPE)
            {
                std::cerr << "Error sending number due to a connection issue" << std::endl;

                return false;
            }
            std::cerr << "Error sending the number " << std::endl;

            return false;
        }

        return true;
    }
    catch (const std::exception &e)
    {
        // Catch the exception and handle it
        std::cerr << "Exception: " << e.what() << std::endl;
        return false;
    }
}

void clear_vec(vector<unsigned char> &v)
{
    if (!v.empty())
    {
        v.assign(v.size(), '0');
        v.clear();
    }
}