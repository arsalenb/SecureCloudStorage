
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

bool encryptTextAES(vector<unsigned char> &clear_buf, vector<unsigned char> sessionKey, vector<unsigned char> &cphr_buf, vector<unsigned char> &iv)
{
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    int iv_len = EVP_CIPHER_iv_length(cipher);
    int block_size = EVP_CIPHER_block_size(cipher);
    size_t clear_size = clear_buf.size();

    int cphr_size;

    int key_len = EVP_CIPHER_key_length(cipher);
    vector<unsigned char> key = sessionKey;

    // Allocate memory for and randomly generate IV:
    // Allocate memory for and randomly generate IV:
    iv.resize(iv_len);
    RAND_poll();
    if (RAND_bytes(iv.data(), iv_len) != 1)
    {
        cerr << "Error: RAND_bytes failed for IV\n";
        return false;
    }

    if (clear_size > INT_MAX - block_size)
    {
        cerr << "Error: integer overflow (file too big?)\n";
        return false;
    }

    // allocate a buffer for the ciphertext:
    int enc_buffer_size = clear_size + block_size;
    cphr_buf.resize(enc_buffer_size);

    // Create and initialise the context with the used cipher, key, and iv
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n";
        return false;
    }

    int ret = EVP_EncryptInit(ctx, cipher, key.data(), iv.data());
    if (ret != 1)
    {
        cerr << "Error: EncryptInit Failed\n";
        return false;
    }

    int update_len = 0; // bytes encrypted at each chunk
    int total_len = 0;  // total encrypted bytes

    // Encrypt Update: one call is enough because  the data is small.
    ret = EVP_EncryptUpdate(ctx, cphr_buf.data(), &update_len, clear_buf.data(), clear_size);
    if (ret != 1)
    {
        cerr << "Error: EncryptUpdate Failed\n";
        return false;
    }
    total_len += update_len;

    // Encrypt Final. Finalize the encryption and add padding
    ret = EVP_EncryptFinal(ctx, cphr_buf.data() + total_len, &update_len);
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

bool decryptTextAES(vector<unsigned char> &cphr_buf, vector<unsigned char> &sessionKey, vector<unsigned char> &iv, vector<unsigned char> &clear_buf)
{
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    int block_size = EVP_CIPHER_block_size(cipher);
    int cphr_size = cphr_buf.size();

    vector<unsigned char> key = sessionKey;

    // Allocate memory for the decrypted text

    clear_buf.resize(cphr_size); // Maximum size

    // Create and initialise the context with the used cipher, key, and iv
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n";
        return false;
    }

    int ret = EVP_DecryptInit(ctx, cipher, key.data(), iv.data());
    if (ret != 1)
    {
        cerr << "Error: DecryptInit Failed\n";
        return false;
    }

    int update_len = 0; // bytes decrypted at each chunk
    int total_len = 0;  // total decrypted bytes

    // Decrypt Update: one call is enough because the data is small.
    ret = EVP_DecryptUpdate(ctx, clear_buf.data(), &update_len, cphr_buf.data(), cphr_size);
    if (ret != 1)
    {
        cerr << "Error: DecryptUpdate Failed\n";
        return false;
    }
    total_len += update_len;

    // Decrypt Final. Finalize the decryption and remove padding
    ret = EVP_DecryptFinal(ctx, clear_buf.data() + total_len, &update_len);
    if (ret != 1)
    {
        cerr << "Error: DecryptFinal Failed\n";
        return false;
    }
    total_len += update_len;
    vector<unsigned char> cut_clear_buff;
    cut_clear_buff.insert(cut_clear_buff.begin(), clear_buf.begin(), clear_buf.begin() + total_len);
    clear_buf = cut_clear_buff;
    // Delete the context and the key from memory
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool generateSessionKey(vector<unsigned char> &digest, vector<unsigned char> &sessionKey)
{
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();

    int sessionKeyLength = EVP_CIPHER_key_length(cipher);

    sessionKey.resize(sessionKeyLength);
    std::copy(digest.begin(), digest.begin() + sessionKeyLength, sessionKey.begin());

    printf("Session key is:\n");
    for (unsigned int n = 0; n < sessionKeyLength; n++)
        printf("%02x", sessionKey[n]);
    printf("\n");

    return true;
}