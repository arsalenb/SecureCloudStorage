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
typedef std::vector<unsigned char> Buffer;

const int Max_Ephemral_Public_Key_Size = 2048;
const int Encrypted_Signature_Size = 272; // 256 for the signature +16 for the aes padding block
const int CBC_IV_Length = EVP_CIPHER_iv_length(EVP_aes_128_cbc());

bool receiveEphemeralPublicKey(int clientSocket, EVP_PKEY *&deserializedKey, Buffer &serializedKey);
bool generateDigitalSignature(Buffer &data, EVP_PKEY *privateKey, Buffer &signature);

bool verifyDigitalSignature(Buffer &data, Buffer &signature, EVP_PKEY *publicKey);
bool computeSHA256Digest(Buffer &data, Buffer &digest);
void serializeLoginMessageFromTheServer(Buffer &serializedServerEphemralKey,
                                        Buffer &cipher_text, Buffer &iv, Buffer &sendBuffer);
bool deserializeLoginMessageFromTheServer(Buffer &receivedBuffer,
                                          Buffer &serializedServerEphemralKey,
                                          Buffer &cipher_text, Buffer &iv);
bool serializeLoginMessageFromTheClient(Buffer &cipher_text, Buffer &iv, Buffer &sendBuffer);
void deserializeLoginMessageFromTheClient(Buffer &receivedBuffer,
                                          Buffer &cipher_text, Buffer &iv);

size_t calLengthLoginMessageFromTheServer();
bool loadPrivateKey(std::string privateKeyPath, EVP_PKEY *&privateKey, string pem_pas);
bool loadPublicKey(const std::string publicKeyPath, EVP_PKEY *&publicKey);
bool sendData(int socket, Buffer &data);
bool receiveData(int socket, Buffer &buffer);
bool receiveSize(int socket, size_t &number);
bool sendSize(int socket, size_t number);
void clear_vec(Buffer &v);
int incrementCounter(int counter);

#endif
