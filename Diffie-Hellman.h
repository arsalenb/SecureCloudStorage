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

static DH* get_dh2048(void);
int handleErrors();
EVP_PKEY* diffieHellmanKeyGeneration();
unsigned char* serializePublicKey(EVP_PKEY* DH_Keys, int* keyLength);
EVP_PKEY* deserializePublicKey( unsigned char* buffer, int bufferLen);
int derive_shared_secret(EVP_PKEY *my_dhkey, EVP_PKEY *peer_pubkey,unsigned char*& skey, size_t& skeylen);

#endif // MYOPENSSL_H
