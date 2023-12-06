
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

const int Max_Public_Key_Size = 2048;
static DH *get_dh2048(void)
{
    static unsigned char dhp_2048[] = {
        0xD5, 0x07, 0x6B, 0x74, 0x73, 0x27, 0x2D, 0xB6, 0x67, 0x12,
        0x98, 0xED, 0x46, 0xF3, 0x23, 0x4E, 0xF3, 0x64, 0xB6, 0x29,
        0x9D, 0x52, 0x9F, 0x3A, 0xDC, 0xAB, 0xFA, 0x26, 0x89, 0xD1,
        0x30, 0x59, 0x29, 0x63, 0x8C, 0xAC, 0x72, 0x95, 0x9D, 0xDF,
        0xDC, 0x4A, 0x5A, 0x87, 0xF1, 0xC6, 0x35, 0x2E, 0xA9, 0x66,
        0x68, 0xD5, 0xE7, 0x4A, 0x5F, 0x53, 0xA7, 0x04, 0x4F, 0x9D,
        0xB6, 0x51, 0x0B, 0x07, 0x27, 0xB9, 0x8A, 0x77, 0x93, 0x3E,
        0x45, 0x27, 0xAD, 0xE3, 0xF7, 0x1B, 0xBD, 0x9C, 0xF9, 0x5B,
        0x5F, 0x43, 0xA1, 0x65, 0xA1, 0xE0, 0xA3, 0x71, 0xBD, 0x1D,
        0x51, 0xAA, 0x71, 0xAB, 0x65, 0xB1, 0x87, 0x8D, 0xD3, 0x8E,
        0x7C, 0xB9, 0x99, 0x77, 0xF1, 0xA8, 0xC6, 0xDD, 0xE9, 0x2E,
        0x0B, 0x6D, 0x15, 0x23, 0xBF, 0x6F, 0x66, 0x82, 0x09, 0xF5,
        0xDE, 0xAA, 0x4F, 0x30, 0xCE, 0xD1, 0x5B, 0xD6, 0xFD, 0x50,
        0x28, 0xCC, 0x38, 0x40, 0x8B, 0x4A, 0xC9, 0x9C, 0x01, 0xDC,
        0x5E, 0xA8, 0x02, 0x30, 0xF0, 0xDF, 0x68, 0x15, 0x88, 0xC1,
        0x5A, 0x6D, 0x62, 0x82, 0xAB, 0x48, 0x05, 0x29, 0xDE, 0x30,
        0x90, 0x24, 0x5D, 0x4D, 0x1D, 0xB0, 0x1D, 0xF2, 0x3C, 0xC7,
        0xDB, 0xCF, 0x25, 0x6F, 0x5E, 0xA4, 0x39, 0x7D, 0x84, 0x84,
        0x43, 0x3F, 0xEE, 0x93, 0x29, 0x04, 0xC0, 0xE0, 0x0B, 0x50,
        0x1B, 0x37, 0x72, 0x8F, 0x02, 0x5F, 0xEB, 0x7B, 0x60, 0x0B,
        0xA5, 0xF4, 0xAC, 0x01, 0xA2, 0x8D, 0x33, 0xB0, 0xA1, 0x77,
        0xEC, 0xEF, 0x47, 0xE2, 0x6C, 0xB6, 0x1E, 0xE5, 0x41, 0x50,
        0xFB, 0xF3, 0x67, 0xF7, 0x4D, 0xED, 0x12, 0x28, 0x64, 0xB6,
        0x5A, 0xA7, 0xE0, 0xB6, 0x17, 0x1F, 0xFC, 0x26, 0xE3, 0x35,
        0x58, 0xB6, 0xA1, 0x0E, 0x30, 0x53, 0x7E, 0x8F, 0x2A, 0x1E,
        0xE3, 0xAE, 0x44, 0xD0, 0x11, 0xA3};
    static unsigned char dhg_2048[] = {
        0x02};
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
    g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
    if (p == NULL || g == NULL || !DH_set0_pqg(dh, p, NULL, g))
    {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}
int handleErrors()
{
    printf("An error occourred.\n");
    exit(1);
}

EVP_PKEY *diffieHellmanKeyGeneration()
{
    /*GENERATING  EPHEMERAL KEY*/

    EVP_PKEY *params;
    if (NULL == (params = EVP_PKEY_new()))
        handleErrors();
    DH *temp = get_dh2048();
    if (1 != EVP_PKEY_set1_DH(params, temp))
        handleErrors();
    DH_free(temp);
    /* Create context for the key generation */
    EVP_PKEY_CTX *DHctx;
    if (!(DHctx = EVP_PKEY_CTX_new(params, NULL)))
        handleErrors();
    /* Generate a new key */
    EVP_PKEY *dhkeys = NULL;
    if (1 != EVP_PKEY_keygen_init(DHctx))
        handleErrors();
    if (1 != EVP_PKEY_keygen(DHctx, &dhkeys))
        handleErrors();

    // FREE EVERYTHING INVOLVED WITH THE EXCHANGE (not the shared secret tho)

    EVP_PKEY_CTX_free(DHctx);
    EVP_PKEY_free(params);
    return dhkeys;
}

// serialize public key deffie-hellman
unsigned char *serializePublicKey(EVP_PKEY *DH_Keys, int *keyLength)
{
    BIO *bio;
    int ret;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
        return NULL;
    // retrrive the public key
    ret = PEM_write_bio_PUBKEY(bio, DH_Keys);
    if (ret != 1)
        return NULL;

    // Read the key into a dynamically allocated buffer
    unsigned char *keyBuffer = NULL;
    *keyLength = BIO_pending(bio);
    if (*keyLength > 0)
    {
        keyBuffer = (unsigned char *)malloc(*keyLength);
        if (keyBuffer == NULL)
            return NULL;

        ret = BIO_read(bio, keyBuffer, *keyLength);
        printf("Public Key:\n%s\n", keyBuffer);
        if (ret <= 0)
        {
            free(keyBuffer);
            return NULL;
        }
    }

    BIO_free(bio);

    return keyBuffer;
}

// Function that allocates and returns the deserialized public key. It returns NULL in case of error
EVP_PKEY *deserializePublicKey(unsigned char *buffer, int bufferLen)
{
    EVP_PKEY *pubKey;
    int ret;
    BIO *myBio;
    myBio = BIO_new(BIO_s_mem());
    if (myBio == NULL)
        return NULL;
    ret = BIO_write(myBio, buffer, bufferLen);
    if (ret <= 0)
        return NULL;
    pubKey = PEM_read_bio_PUBKEY(myBio, NULL, NULL, NULL);
    if (pubKey == NULL)
        return NULL;
    BIO_free(myBio);
    return pubKey;
}

int derive_shared_secret(EVP_PKEY *my_dhkey, EVP_PKEY *peer_pubkey, unsigned char *&skey, size_t &skeylen)
{
    EVP_PKEY_CTX *derive_ctx;

    /* Creating a context for key derivation */
    derive_ctx = EVP_PKEY_CTX_new(my_dhkey, NULL);
    if (!derive_ctx)
    {
        fprintf(stderr, "Error creating context\n");
        return -1;
    }

    /* Initializing key derivation */
    if (EVP_PKEY_derive_init(derive_ctx) <= 0)
    {
        fprintf(stderr, "Error initializing key derivation\n");
        EVP_PKEY_CTX_free(derive_ctx);
        return -1;
    }

    /* Setting the peer with its public key */
    if (EVP_PKEY_derive_set_peer(derive_ctx, peer_pubkey) <= 0)
    {
        fprintf(stderr, "Error setting peer public key\n");
        EVP_PKEY_CTX_free(derive_ctx);
        return -1;
    }

    /* Determine buffer length, by performing a derivation but writing the result nowhere */
    if (EVP_PKEY_derive(derive_ctx, NULL, &skeylen) <= 0)
    {
        fprintf(stderr, "Error determining buffer length\n");
        EVP_PKEY_CTX_free(derive_ctx);
        return -1;
    }

    /* Allocate buffer for the shared secret */
    skey = (unsigned char *)(malloc(skeylen));
    if (!skey)
    {
        fprintf(stderr, "Error allocating memory for shared secret\n");
        EVP_PKEY_CTX_free(derive_ctx);
        return -1;
    }

    /* Perform the derivation and store it in skey buffer */
    if (EVP_PKEY_derive(derive_ctx, skey, &skeylen) <= 0)
    {
        fprintf(stderr, "Error deriving shared secret\n");
        free(skey);
        EVP_PKEY_CTX_free(derive_ctx);
        return -1;
    }
    printf("shared Key :\n%s\n", skey);

    EVP_PKEY_CTX_free(derive_ctx);

    return 0; // Success
}

// concatinate (g^b,g^a)
void concatenateKeys(int serializedServerKeyLength, int serializedClientKeyLength,
                     const unsigned char *serializedServerKey, const unsigned char *serializedClientKey,
                     unsigned char *&concatenatedKeys, int concatenatedkeysLength)
{

    // Allocate memory for the concatenated keys
    concatenatedKeys = (unsigned char *)malloc(concatenatedkeysLength);

    // Concatenate the serialized keys
    std::memcpy(concatenatedKeys, serializedServerKey, serializedServerKeyLength);
    std::memcpy(concatenatedKeys + serializedServerKeyLength, serializedClientKey, serializedClientKeyLength);
}
