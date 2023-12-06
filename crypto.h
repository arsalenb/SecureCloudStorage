#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <cstring>
using namespace std;

bool encryptTextAES(unsigned char *clear_buf, int clear_size, unsigned char *sessionKey, unsigned char *&cphr_buf, int &cphr_size, unsigned char *&iv);
bool decryptTextAES(unsigned char *cphr_buf, int cphr_size, unsigned char *sessionKey, unsigned char *iv, unsigned char *&clear_buf, int &clear_size);