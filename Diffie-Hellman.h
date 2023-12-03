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
char* serializePublicKey(EVP_PKEY* DH_Keys, int* keyLength);
EVP_PKEY* deserializePublicKey( char* buffer, int bufferLen);

#endif // MYOPENSSL_H
