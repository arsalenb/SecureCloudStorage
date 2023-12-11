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

bool encryptTextAES(std::vector<unsigned char> &clear_buf, std::vector<unsigned char> sessionKey, std::vector<unsigned char> &cphr_buf, std::vector<unsigned char> &iv);
bool decryptTextAES(vector<unsigned char> &cphr_buf, vector<unsigned char> &sessionKey, vector<unsigned char> &iv, vector<unsigned char> &clear_buf);
bool generateSessionKey(vector<unsigned char> &digest, vector<unsigned char> &sessionKey);