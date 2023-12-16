
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
#include <crypto.h>
#include <openssl/err.h>
#include <constants.h>

using namespace std;
typedef vector<unsigned char> Buffer;

namespace crypto
{
    const EVP_CIPHER *cipher = EVP_aes_128_ccm();
    const int IV_LENGTH = EVP_CIPHER_iv_length(cipher);
    const int TAG_LENGTH = 14; // self-chosen to be on 14 bytes (valid sizes are: 4, 6, 10, 12, 14 and 16 bytes)
    const int BLOCK_SIZE = EVP_CIPHER_block_size(cipher);
    const int KEY_LEN = EVP_CIPHER_key_length(cipher);

}

bool encryptTextAES(Buffer &clear_buf, Buffer sessionKey, Buffer &cphr_buf, Buffer &iv)
{
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    int iv_len = EVP_CIPHER_iv_length(cipher);
    int block_size = EVP_CIPHER_block_size(cipher);
    size_t clear_size = clear_buf.size();

    int cphr_size;

    int key_len = EVP_CIPHER_key_length(cipher);
    Buffer key = sessionKey;

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

bool decryptTextAES(Buffer &cphr_buf, Buffer &sessionKey, Buffer &iv, Buffer &clear_buf)
{
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    int block_size = EVP_CIPHER_block_size(cipher);
    int cphr_size = cphr_buf.size();

    Buffer key = sessionKey;

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
    Buffer cut_clear_buff;
    cut_clear_buff.insert(cut_clear_buff.begin(), clear_buf.begin(), clear_buf.begin() + total_len);
    clear_buf = cut_clear_buff;
    // Delete the context and the key from memory
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool generateSessionKey(Buffer &digest, Buffer &sessionKey)
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
};

bool encrypt_aes_ccm(Buffer clear_buf, Buffer &cphr_buf, Buffer sessionKey, Buffer iv, Buffer aad, Buffer &tag)
{
    size_t clear_size = clear_buf.size();

    if (clear_size > INT_MAX - crypto::BLOCK_SIZE)
    {
        cerr << "[AES_CCM_ENCRYPT] integer overflow\n";
        return 0;
    }

    // Allocate a space on the buffer for the ciphertext:
    cphr_buf.resize(clear_size); // Since encryption is done using the streaming mode CTR, the ciphertext will be exactly as long as the plaintext.

    // Create and initialise the context
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        cerr << "[AES_CCM_ENCRYPT] EVP_CIPHER_CTX_new returned NULL\n";
        return 0;
    }
    if (!EVP_CIPHER_CTX_init(ctx))
    {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "[AES_CCM_ENCRYPT] EVP_CIPHER_CTX_new returned NULL\n";
        return 0;
    }

    // Initialize the context with the algorithm
    if (EVP_EncryptInit(ctx, crypto::cipher, 0, 0) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "[AES_CCM_ENCRYPT] Context initialization Failed\n";
        return 0;
    }

    // Set iv and tag sizes
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, crypto::IV_LENGTH, 0);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, crypto::TAG_LENGTH, 0);

    // Set the key and the iv
    if (EVP_EncryptInit(ctx, 0, sessionKey.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "[AES_CCM_ENCRYPT] EncryptInit Failed\n";
        return 0;
    }
    // Provide to algorithm the size to encrypt
    int out_len = 0;
    int total_len = 0;

    if (EVP_EncryptUpdate(ctx, 0, &out_len, 0, clear_size) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "[AES_CCM_ENCRYPT] EncryptUpdate Failed\n";
        return 0;
    }

    // Provide AAD data
    if (EVP_EncryptUpdate(ctx, 0, &out_len, aad.data(), aad.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "[AES_CCM_ENCRYPT] Providing AAD Failed\n";
        return 0;
    }
    // Now we encrypt the data in clear_buf, placing the output in cphr_buf
    if (EVP_EncryptUpdate(ctx, cphr_buf.data(), &out_len, clear_buf.data(), clear_size) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "[AES_CCM_ENCRYPT] EVP_EncryptUpdate Failed\n";
        return 0;
    }

    // Finalize the encryption
    total_len += out_len;
    if (EVP_EncryptFinal(ctx, cphr_buf.data() + total_len, &out_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "[AES_CCM_ENCRYPT] EVP_EncryptFinal Failed \n";
        return 0;
    }
    // Extract the tag(MAC)
    tag.resize(crypto::TAG_LENGTH);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, crypto::TAG_LENGTH, tag.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "[AES_CCM_ENCRYPT] Tag extraction Failed \n";
        return 0;
    }

    // free the context from memory
    EVP_CIPHER_CTX_free(ctx);

    return 1;
}

bool decrypt_aes_ccm(Buffer cphr_buf, Buffer &clear_buf, Buffer sessionKey, Buffer iv, Buffer aad, Buffer tag)
{
    int cphr_size = cphr_buf.size();

    // Allocate memory for the decrypted text
    clear_buf.resize(cphr_size);

    // Create and initialise the context
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    if (!ctx)
    {
        cerr << "[AES_CCM_DECRYPT] EVP_CIPHER_CTX_new returned NULL\n";
        return 0;
    }
    if (!EVP_CIPHER_CTX_init(ctx))
    {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "[AES_CCM_DECRYPT] EVP_CIPHER_CTX_new returned NULL\n";
        return 0;
    }
    // Set algorithm to context
    if (EVP_DecryptInit(ctx, crypto::cipher, 0, 0) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "[AES_CCM_AES_CCM_DECRYPT] Context initialization Failed\n";
        return 0;
    }
    // Set the iv  size
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, crypto::IV_LENGTH, 0);

    // Set the tag associated with encrypted data
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, crypto::TAG_LENGTH, tag.data());

    // Set the key and the iv
    if (EVP_DecryptInit(ctx, 0, sessionKey.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "[AES_CCM_DECRYPT] DecryptInit Failed\n";
        return 0;
    }
    // Provide to algorithm the size to decrypt
    int out_len = 0;
    int total_len = 0;

    if (EVP_DecryptUpdate(ctx, 0, &out_len, 0, cphr_size) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "[AES_CCM_DECRYPT] DecryptUpdate Failed\n";
        return 0;
    }
    // Add AAD for verification

    if (EVP_DecryptUpdate(ctx, 0, &out_len, aad.data(), aad.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "[AES_CCM_DECRYPT] AAD verification didn't pass\n";
        return 0;
    }

    // Now we decrypt and insert in clear_buf
    if (EVP_DecryptUpdate(ctx, clear_buf.data(), &out_len, cphr_buf.data(), cphr_size) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "[AES_CCM_DECRYPT] DecryptUpdate Failed\n";
        ERR_print_errors_fp(stderr);

        return 0;
    }

    total_len += out_len;

    // Decrypt Final. Finalize the decryption and remove padding
    if (EVP_DecryptFinal(ctx, clear_buf.data() + total_len, &out_len) != 1)
    {
        cerr << "[AES_CCM_DECRYPT] DecryptFinal Failed\n";
        return 0;
    }
    total_len += out_len;

    // Cut the vector size to the total length decrypted
    vector<unsigned char> cut_clear_buff;
    cut_clear_buff.insert(cut_clear_buff.begin(), clear_buf.begin(), clear_buf.begin() + total_len);
    clear_buf = cut_clear_buff;

    // Delete the context and the key from memory
    EVP_CIPHER_CTX_free(ctx);

    return 1;
}

int generateRandomValue(Buffer &value, int length)
{
    value.resize(length);

    if (RAND_poll() != 1)
    {
        cerr << "Error in RAND_poll\n";
        return 0;
    }
    if (RAND_bytes(value.data(), length) != 1)
    {
        cerr << "Error in RAND_bytes\n";
        return 0;
    }

    return 1;
}