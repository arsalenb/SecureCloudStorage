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

bool receiveEphemeralPublicKey(int clientSocket, EVP_PKEY *&deserializedKey, std::vector<unsigned char> &serializedKey);
bool generateDigitalSignature(std::vector<unsigned char> &data, EVP_PKEY *privateKey, std::vector<unsigned char> &signature);

bool verifyDigitalSignature(vector<unsigned char> &data, vector<unsigned char> &signature, EVP_PKEY *publicKey);
bool computeSHA256Digest(std::vector<unsigned char> &data, std::vector<unsigned char> &digest);
bool serializeLoginMessageFromTheServer(vector<unsigned char> &serializedServerEphemralKey,
                                        vector<unsigned char> &cipher_text, vector<unsigned char> &iv, vector<unsigned char> &sendBuffer);
bool deserializeLoginMessageFromTheServer(vector<unsigned char> &receivedBuffer,
                                          vector<unsigned char> &serializedServerEphemralKey,
                                          vector<unsigned char> &cipher_text, vector<unsigned char> &iv);
bool serializeLoginMessageFromTheClient(vector<unsigned char> &cipher_text, vector<unsigned char> &iv, vector<unsigned char> &sendBuffer);
bool deserializeLoginMessageFromTheClient(vector<unsigned char> &receivedBuffer,
                                          vector<unsigned char> &cipher_text, vector<unsigned char> &iv);

size_t calLengthLoginMessageFromTheServer();
bool loadPrivateKey(std::string privateKeyPath, EVP_PKEY *&privateKey);
bool loadPublicKey(const std::string publicKeyPath, EVP_PKEY *&publicKey);
bool sendData(int socket, std::vector<unsigned char> &data);
bool receiveData(int socket, std::vector<unsigned char> &buffer, size_t bufferSize);
bool receiveNumber(int socket, size_t &number);
bool sendNumber(int socket, size_t number);
int generateRandomValue(std::vector<unsigned char> &value, int length);
#endif
