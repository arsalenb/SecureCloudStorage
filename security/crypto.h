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

typedef std::vector<unsigned char> Buffer;

bool encryptTextAES(Buffer &clear_buf, Buffer sessionKey, Buffer &cphr_buf, Buffer &iv);
bool decryptTextAES(Buffer &cphr_buf, Buffer &sessionKey, Buffer &iv, Buffer &clear_buf);
void generateSessionKey(Buffer &digest, Buffer &sessionKey);
bool encrypt_aes_ccm(Buffer clear_buf, Buffer &cphr_buf, Buffer sessionKey, Buffer iv, Buffer aad, Buffer &tag);
bool decrypt_aes_ccm(Buffer cphr_buf, Buffer &clear_buf, Buffer sessionKey, Buffer iv, Buffer aad, Buffer tag);
int generateRandomValue(Buffer &value, int length);