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
EVP_PKEY *deserializePublicKey(std::vector<unsigned char> &sKeyBuffer);
int deriveSharedSecret(EVP_PKEY *hostKey, EVP_PKEY *peerKey, std::vector<unsigned char> &sharedKey);

#endif // MYOPENSSL_H
