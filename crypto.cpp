
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

bool encryptTextAES(unsigned char *clear_buf, int clear_size, unsigned char *sessionKey, unsigned char *&cphr_buf, int &cphr_size, unsigned char *&iv)
{
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    int iv_len = EVP_CIPHER_iv_length(cipher);
    int block_size = EVP_CIPHER_block_size(cipher);

    int key_len = EVP_CIPHER_key_length(cipher);
    unsigned char *key = (unsigned char *)malloc(key_len);
    memcpy(key, sessionKey, key_len);

    // Allocate memory for and randomly generate IV:
    iv = (unsigned char *)malloc(iv_len);
    RAND_poll();
    RAND_bytes((unsigned char *)&iv[0], iv_len);

    if (clear_size > INT_MAX - block_size)
    {
        cerr << "Error: integer overflow (file too big?)\n";
        return false;
    }

    // allocate a buffer for the ciphertext:
    int enc_buffer_size = clear_size + block_size;
    cphr_buf = (unsigned char *)malloc(enc_buffer_size);
    if (!cphr_buf)
    {
        cerr << "Error: malloc returned NULL (file too big?)\n";
        return false;
    }

    // Create and initialise the context with the used cipher, key, and iv
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n";
        return false;
    }

    int ret = EVP_EncryptInit(ctx, cipher, key, iv);
    if (ret != 1)
    {
        cerr << "Error: EncryptInit Failed\n";
        return false;
    }

    int update_len = 0; // bytes encrypted at each chunk
    int total_len = 0;  // total encrypted bytes

    // Encrypt Update: one call is enough because  the data is small.
    ret = EVP_EncryptUpdate(ctx, cphr_buf, &update_len, clear_buf, clear_size);
    if (ret != 1)
    {
        cerr << "Error: EncryptUpdate Failed\n";
        return false;
    }
    total_len += update_len;

    // Encrypt Final. Finalize the encryption and add padding
    ret = EVP_EncryptFinal(ctx, cphr_buf + total_len, &update_len);
    if (ret != 1)
    {
        cerr << "Error: EncryptFinal Failed\n";
        return false;
    }
    total_len += update_len;

    cphr_size = total_len;

    // delete the context and the plaintext from memory
    EVP_CIPHER_CTX_free(ctx);

    return true;
}