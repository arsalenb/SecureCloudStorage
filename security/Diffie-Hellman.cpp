
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
#include <openssl/ec.h>
#include <openssl/evp.h>

using namespace std;

const int Max_Public_Key_Size = 2048;

/// @brief Generates an elliptic curve diffie–hellman key paremeters and a key
/// @return EVP_PKEY on success, nullptr on failure,
EVP_PKEY *ECDHKeyGeneration()
{

    EVP_PKEY_CTX *paramsCtx, *keyCtx;
    EVP_PKEY *ECDHparams = NULL, *pKey = NULL;

    /* Create the context for ECDH parameter generation */
    if (!(paramsCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)))
    {
        cerr << "[ECDH] DH context creation failed" << endl;
        return nullptr;
    }

    /* Initialise the parameter generation */
    if (1 != EVP_PKEY_paramgen_init(paramsCtx))
    {
        cerr << "[ECDH] DH parameters generation initialisation failed" << endl;
        EVP_PKEY_CTX_free(paramsCtx);
        return nullptr;
    }

    /* We choose ANSI X9.62 Prime 256v1 curve */
    if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramsCtx, NID_X9_62_prime256v1))
    {
        cerr << "[ECDH] DH parameters generation failed" << endl;
        EVP_PKEY_CTX_free(paramsCtx);
        return nullptr;
    }

    /* Generate the ECDH parameters */
    if (!EVP_PKEY_paramgen(paramsCtx, &ECDHparams))
    {
        cerr << "[ECDH] DH parameters generation failed" << endl;
        EVP_PKEY_CTX_free(paramsCtx);
        EVP_PKEY_free(ECDHparams);
        return nullptr;
    }

    /* Create the context in order to generate key initialized with ECDH params */
    if (!(keyCtx = EVP_PKEY_CTX_new(ECDHparams, NULL)))
    {
        cerr << "[ECDH] Key generation context creation failed" << endl;
        EVP_PKEY_CTX_free(paramsCtx);
        EVP_PKEY_free(ECDHparams);
        return nullptr;
    }

    /* Initialise and generate the private key (includes public key) */
    if (1 != EVP_PKEY_keygen_init(keyCtx))
    {
        cerr << "[ECDH] Key generation  failed" << endl;
        EVP_PKEY_CTX_free(paramsCtx);
        EVP_PKEY_CTX_free(keyCtx);
        EVP_PKEY_free(ECDHparams);
        return nullptr;
    }
    if (1 != EVP_PKEY_keygen(keyCtx, &pKey))
    {
        cerr << "[ECDH] Key generation  failed" << endl;
        EVP_PKEY_CTX_free(paramsCtx);
        EVP_PKEY_CTX_free(keyCtx);
        EVP_PKEY_free(ECDHparams);
        return nullptr;
    }

    // Free memory
    EVP_PKEY_CTX_free(paramsCtx);
    EVP_PKEY_CTX_free(keyCtx);
    EVP_PKEY_free(ECDHparams);

    return pKey;
}

/// @brief Serializes an ECDH public key to a memory buffer in PEM format.
/// @param public_key EVP_PKEY object representing the public key to be serialized.
/// @param sKeyBuffer A reference to the buffer where the serialized key will be stored.
/// @param sKeyLength A reference to the size_t variable that will store the length of the serialized key.
/// @return 1 on success, 0 on failure.
int serializePubKey(EVP_PKEY *public_key, vector<unsigned char> &sKeyBuffer)
{
    size_t sKeyLength;

    // Allocate an instance of the BIO structure for serialization
    BIO *bio = BIO_new(BIO_s_mem());

    if (!bio)
    {
        cerr << "[ECDH] Failed to create BIO" << endl;
        return 0;
    }

    // Serialize a key into PEM format and write it in the BIO
    if (PEM_write_bio_PUBKEY(bio, public_key) != 1)
    {
        cerr << "[ECDH] Failed to write public key into BIO" << endl;
        BIO_free(bio);
        return 0;
    }
    // Set of the pointer key_buffer to the buffer of the memory bio and return its size
    unsigned char *pointer;
    sKeyLength = BIO_get_mem_data(bio, &pointer); // exit on key length <=
    sKeyBuffer.insert(sKeyBuffer.begin(), pointer, pointer + sKeyLength);

    // Cleanup
    BIO_free(bio);

    return 1;
}

/// @brief Deserializes an ECDH public key from a buffer
/// @param sKeyBuffer Pointer to the buffer containing the serialized public key
/// @param sKeyLength Length of the serialized public key buffer
/// @return pointer to the deserialized public key (EVP_PKEY*) on success, or nullptr on failure
EVP_PKEY *deserializePublicKey(std::vector<unsigned char> &sKeyBuffer)
{
    EVP_PKEY *pubKey;
    int ret;
    BIO *bio;

    // Allocate an instance of the BIO structure for deserialization
    bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        cerr << "[ECDH] Failed to create BIO" << endl;
        return nullptr;
    }
    std::vector<unsigned char>::iterator it;

    // Write serialized the key from the buffer in bio
    ret = BIO_write(bio, sKeyBuffer.data(), sKeyBuffer.size());
    if (ret <= 0)
    {
        cerr << "[ECDH] BIO_write failed" << endl;
        return nullptr;
    }

    // Reads a key written in PEM format from the bio and deserialize it
    pubKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (!pubKey)
    {
        cerr << "[ECDH] PEM_read_bio_PUBKEY failed" << endl;
        return nullptr;
    }

    BIO_free(bio);
    return pubKey;
}

/// @brief Function to derive a shared secret using Elliptic Curve Diffie-Hellman (ECDH)
/// @param hostKey The ECDH public key of the host
/// @param peerKey The ECDH public key of the peer
/// @param sharedKey  a pointer that will hold the derived shared secret
/// @param sharedKeyLength Reference to a size_t variable that will hold the length of the derived shared secret
/// @return 1 on success, 0 on failure
int deriveSharedSecret(EVP_PKEY *hostKey, EVP_PKEY *peerKey, vector<unsigned char> &sharedKey)
{

    size_t sharedKeyLength; // Variable to store the shared key length
    // Create a new context for deriving ECDH secret
    EVP_PKEY_CTX *deriveCtx = EVP_PKEY_CTX_new(hostKey, NULL);
    if (!deriveCtx)
    {
        cerr << "[ECDH] shared key derivation context creation failed" << endl;
        return 0;
    }

    // Initializing key derivation
    if (1 != EVP_PKEY_derive_init(deriveCtx))
    {
        cerr << "[ECDH] shared key derivation initialization failed" << endl;
        EVP_PKEY_CTX_free(deriveCtx);
        return 0;
    }

    // Provide peer public key
    if (1 != EVP_PKEY_derive_set_peer(deriveCtx, peerKey))
    {
        cerr << "[ECDH] setting peer public key failed" << endl;
        EVP_PKEY_CTX_free(deriveCtx);
        return 0;
    }

    // Determine buffer length for shared secret
    if (1 != EVP_PKEY_derive(deriveCtx, NULL, &sharedKeyLength))
    {
        cerr << "[ECDH] determining buffer length failed" << endl;
        EVP_PKEY_CTX_free(deriveCtx);
        return 0;
    }

    sharedKey.resize(sharedKeyLength);
    // Perform the derivation of secret and store it in buffer
    if (1 != EVP_PKEY_derive(deriveCtx, sharedKey.data(), &sharedKeyLength))
    {
        cerr << "[ECDH] shared secret derivation failed" << endl;
        EVP_PKEY_CTX_free(deriveCtx);
        return 0;
    }

    EVP_PKEY_CTX_free(deriveCtx);

    return 1;
}

// concatinate (g^b,g^a)
void concatenateKeys(std::vector<unsigned char> &serializedServerKey,
                     std::vector<unsigned char> &serializedClientKey,
                     std::vector<unsigned char> &concatenatedKeys)
{

    // Copy the serialized keys into the concatenatedKeys vector using insert
    concatenatedKeys.insert(concatenatedKeys.begin(), serializedServerKey.begin(), serializedServerKey.end());
    concatenatedKeys.insert(concatenatedKeys.end(), serializedClientKey.begin(), serializedClientKey.end());
}
