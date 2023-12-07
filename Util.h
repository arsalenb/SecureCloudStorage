#ifndef Util
#define Util

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

const int Max_Ephemral_Public_Key_Size = 2048;
const int Encrypted_Signature_Size = 272; // 256 for the signature +16 for the aes padding block
const int CBC_IV_Length = EVP_CIPHER_iv_length(EVP_aes_128_cbc());

bool receiveEphemeralPublicKey(int clientSocket, EVP_PKEY *&deserializedKey, unsigned char *&serializedKey, size_t &serializedKeyLength);
bool generateDigitalSignature(unsigned char *data, size_t dataLength, EVP_PKEY *privateKey, unsigned char *&signature, unsigned int &signatureLength);
bool verifyDigitalSignature(unsigned char *data, size_t dataLength, unsigned char *signature, unsigned int signatureLength, EVP_PKEY *publicKey);
bool computeSHA256Digest(unsigned char *data, size_t dataLength, unsigned char *&digest, unsigned int &digestLength);
bool serializeLoginMessageFromTheServer(unsigned char *serializedServerEphemralKey, int serializedServerrEphemralKeyLength,
                                        unsigned char *cipher_text, unsigned char *iv, unsigned char *&sendBuffer);
bool deserializeLoginMessageFromTheServer(unsigned char *receivedBuffer, unsigned char *&serializedServerEphemralKey, int &serializedServerrEphemralKeyLength,
                                          unsigned char *&cipher_text, unsigned char *&iv);
bool serializeLoginMessageFromTheClient(unsigned char *cipher_text, unsigned char *iv, unsigned char *&sendBuffer);
bool deserializeLoginMessageFromTheClient(const unsigned char *receivedBuffer,
                                          unsigned char *&cipher_text, unsigned char *&iv);

size_t calLengthLoginMessageFromTheServer();
bool loadPrivateKey(std::string privateKeyPath, EVP_PKEY *&privateKey);
bool loadPublicKey(const std::string publicKeyPath, EVP_PKEY *&publicKey);
#endif
