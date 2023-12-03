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

const int Max_Public_Key_Size = 2048;

bool receiveEphemralPublicKey(int clientSocket, EVP_PKEY*& deserializedKey);

#endif 
