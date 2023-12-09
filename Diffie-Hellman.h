#ifndef MYOPENSSL_H
#define MYOPENSSL_H

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

EVP_PKEY *ECDHKeyGeneration();
int serializePubKey(EVP_PKEY *public_key, std::vector<unsigned char> &sKeyBuffer);
EVP_PKEY *deserializePublicKey(unsigned char *sKeyBuffer, size_t sKeyLength);
int deriveSharedSecret(EVP_PKEY *hostKey, EVP_PKEY *peerKey, unsigned char *&sharedKey, size_t &sharedKeyLength);
void concatenateKeys(int serializedServerKeyLength, int serializedClientKeyLength,
                     const unsigned char *serializedServerKey, const unsigned char *serializedClientKey,
                     unsigned char *&concatenatedKeys, int concatenatedkeysLength);

#endif // MYOPENSSL_H
