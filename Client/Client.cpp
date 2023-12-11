#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <limits>
#include "../Diffie-Hellman.h"
#include "../Util.h"
#include "../crypto.h"
#include "Client.h"

using namespace std;
Client::Client()
{
}

bool Client::connectToServer()
{

    // Initialize members and create a socket
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1)
    {
        std::cerr << "Error creating client socket" << std::endl;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr) <= 0)
    {
        std::cerr << "Invalid address/Address not supported" << std::endl;
        // Handle error
        return false;
    }

    if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
        std::cerr << "Error connecting to server" << std::endl;
        // Handle error
        close(clientSocket);
        return false;
    }

    return true;
}

bool Client::sendUsername()
{
    std::cout << "Enter your username (up to 5 characters): ";
    std::cin >> username;

    if (username.size() > MAX_USERNAME_LENGTH)
    {
        std::cerr << "Error: Username is too long. Maximum length is 5 characters." << std::endl;
        return false;
    }

    // Convert the username string to a vector of unsigned char
    std::vector<unsigned char> usernameData(username.begin(), username.end());

    // Call sendData with the username data
    if (!sendData(clientSocket, usernameData))
    {
        // Handle error if sendData fails
        return false;
    }

    return true;
}

bool Client::receiveServerResponse()
{
    int responseSize = 1;
    vector<unsigned char> buffer(responseSize + 1, 0); // +1 for null terminator
    if (!receiveData(clientSocket, buffer, responseSize))
    {
        return false;
    }

    std::string serverResponse(buffer.begin(), buffer.end());
    std::cout << "Server response: " << serverResponse << std::endl;

    // Implement the logic to handle the server response

    if (serverResponse.compare("1") == 0)
    {
        std::cerr << "User does not exist" << std::endl;
        return false;
    }

    // User exists, proceed to receive the server certificate
    X509 *serverCert = nullptr;
    if (receiveServerCertificate(serverCert))
    {
        // Use the server certificate as needed
        std::cout << "Received server certificate successfully" << std::endl;

        const char *caCertFile = "Cloud Storage CA_cert.pem";
        const char *crlFile = "Cloud Storage CA_crl.pem";
        // Load CA certificate
        X509 *caCert = nullptr;
        FILE *caCertFilePtr = fopen(caCertFile, "r");
        if (!caCertFilePtr)
        {
            perror("Error opening CA certificate file");
            return 0;
        }

        caCert = PEM_read_X509(caCertFilePtr, nullptr, nullptr, nullptr);
        fclose(caCertFilePtr);

        if (!caCert)
        {
            ERR_print_errors_fp(stderr);
            return 0;
        }

        // Load CRL
        X509_CRL *crl = nullptr;
        FILE *crlFilePtr = fopen(crlFile, "r");
        if (!crlFilePtr)
        {
            perror("Error opening CRL file");
            X509_free(caCert);
            return 0;
        }

        crl = PEM_read_X509_CRL(crlFilePtr, nullptr, nullptr, nullptr);
        fclose(crlFilePtr);

        if (!crl)
        {
            ERR_print_errors_fp(stderr);
            X509_free(caCert);
            return 0;
        }
        bool verified = verifyServerCertificate(caCert, crl, serverCert);
        if (verified)
        {
            std::cout << "Server certificate verification successful." << std::endl;
        }
        else
        {
            std::cerr << "Server certificate verification failed." << std::endl;
            return 0;
        }

        // Generate the elliptic curve diffie-Hellman keys for the client
        EVP_PKEY *ECDH_Keys;
        if (!(ECDH_Keys = ECDHKeyGeneration()))
        {
            cerr << "[CLIENT] ECDH key generation failed" << endl;
            return 0;
        }

        vector<unsigned char> sClientKey;

        if (!serializePubKey(ECDH_Keys, sClientKey))
        {
            cerr << "[CLIENT] Serialization of public key failed" << endl;
            return 0;
        }

        // Use the serialized key as needed

        // Send the key size to the server
        size_t sClientKeyLength = sClientKey.size();
        if (!sendNumber(clientSocket, sClientKeyLength))
        {
            std::cerr << "Error sending the key size" << std::endl;
            return false;
        }
        // send the DH public key to the server
        if (!sendData(clientSocket, sClientKey))
        {
            return false;
        }

        // receive from the server: (g^b) ,(g^b) size, {<(g^a,g^b)>s}k, IV

        size_t receiveBufferSize = calLengthLoginMessageFromTheServer();
        vector<unsigned char> receiveBuffer;
        receiveBuffer.resize(receiveBufferSize);

        if (!receiveData(clientSocket, receiveBuffer, receiveBufferSize))
        {
            std::cerr << "Error receiving certificate data" << std::endl;
            return false;
        }

        // Variables to store the deserialized components (g^b) ,(g^b) size, {<(g^a,g^b)>s}k, IV
        vector<unsigned char> sServerEphemeralKey;
        int sServerEphemeralKeyLength = 0;
        vector<unsigned char> cipher_text;
        vector<unsigned char> iv;

        // Call the deserialize function
        if (!deserializeLoginMessageFromTheServer(receiveBuffer, sServerEphemeralKey, cipher_text, iv))
        {
            std::cerr << "Error deseiralizing the message" << std::endl;
            return 0;
        }
        sServerEphemeralKeyLength = sServerEphemeralKey.size();
        if (sServerEphemeralKeyLength > Max_Ephemral_Public_Key_Size)
        {
            cerr << "Key size exceeds the max size" << std::endl;
            return 0;
        }

        EVP_PKEY *deserializedServerEphemeralKey = deserializePublicKey(sServerEphemeralKey);
        if (deserializedServerEphemeralKey == NULL)
        {
            cerr << "Error receiving serializing data" << std::endl;
            return 0;
        }

        // calculate (g^a)^b
        vector<unsigned char> sharedSecretKey;
        size_t sharedSecretLength;
        int derivationResult = deriveSharedSecret(ECDH_Keys, deserializedServerEphemeralKey, sharedSecretKey);

        if (derivationResult == -1)
        {
            return 0;
        }
        sharedSecretLength = sharedSecretKey.size();
        // generate session key Sha256((g^a)^b)
        vector<unsigned char> digest;
        unsigned int digestlen;

        if (!computeSHA256Digest(sharedSecretKey, digest))
        {
            return 0;
        }
        digestlen = digest.size();

        // take first 128 of the the digest
        vector<unsigned char> sessionKey;
        if (!generateSessionKey(digest, sessionKey))
        {
            return 0;
        }

        // concatinate (g^b,g^a)
        // Concatenate the serialized keys

        vector<unsigned char> concatenatedKeys;
        int concatenatedkeysLength = sServerEphemeralKeyLength + sClientKeyLength;
        concatenateKeys(sServerEphemeralKey, sClientKey, concatenatedKeys);

        printf("Concatenated keys:\n");
        for (const auto &ch : concatenatedKeys)
        {
            printf("%02x", ch); // Assuming you want to print hexadecimal values
        }
        printf("\n");

        // Now concatenatedKeys contains the serialized form of both keys

        // decrypt  {<(g^a,g^b)>s}k  using the session key
        vector<unsigned char> plaintext;
        int plaintextSize = 0;
        if (!decryptTextAES(cipher_text, sessionKey, iv, plaintext))
        {
            return 0;
        }
        plaintextSize = plaintext.size();

        // verify the <(g^a,g^b)>s
        EVP_PKEY *server_public_key = X509_get_pubkey(serverCert);

        if (!verifyDigitalSignature(concatenatedKeys, plaintext, server_public_key))
        {
            return 0;
        }
        // read user private key
        std::string privateKeyPath = "users/" + username + "/key.pem";
        EVP_PKEY *prvkey = nullptr;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        if (!loadPrivateKey(privateKeyPath, prvkey))
        {
            return 0;
        }

        // create the digiatl signature <(g^a,g^b)>c using the client private key
        vector<unsigned char> signature;

        if (!generateDigitalSignature(concatenatedKeys, prvkey, signature))
        {
            return 0;
        }
        unsigned int signatureLength = signature.size();
        EVP_PKEY_free(prvkey);

        // encrypt  {<(g^a,g^b)>c}k  using the session key
        cipher_text.clear();
        int cipher_size;
        iv.clear();

        if (!encryptTextAES(signature, sessionKey, cipher_text, iv))
        {
            return 0;
        }
        cipher_size = cipher_text.size();

        //  send to the server: {<(g^a,g^b)>c}k, IV
        vector<unsigned char> sendBuffer;
        if (!serializeLoginMessageFromTheClient(cipher_text, iv, sendBuffer))
        {
            return 0;
        }
        if (!sendData(clientSocket, sendBuffer))
        {
            // Handle error if sendData fails
            return false;
        }

        // Cleanup OpenSSL (if not done already)
        EVP_cleanup();

        // Clean up
        X509_free(serverCert);
    }
    else
    {
        std::cerr << "Error receiving server certificate" << std::endl;
    }

    return true;
}

bool Client::receiveServerCertificate(X509 *&serverCert)
{
    // Implement the logic to receive the server certificate

    // Receive the certificate size
    size_t certSize;
    if (!receiveNumber(clientSocket, certSize))
    {
        // Handle the error if receiving data fails
        return false;
    }
    if (certSize > MAX_CERTIFICATE_SIZE)
    {
        std::cerr << "Certificate size exceeds the max size" << std::endl;
        return false;
    }

    // Receive the certificate data
    vector<unsigned char> certBuffer(certSize);
    if (!receiveData(clientSocket, certBuffer, certSize))
    {
        std::cerr << "Error receiving certificate data" << std::endl;
        return false;
    }
    std::cout << "Certificate Buffer: ";
    for (char i : certBuffer)
        std::cout << i << ' ';

    // Create a BIO from the received data
    BIO *bio = BIO_new_mem_buf(certBuffer.data(), certSize);
    if (!bio)
    {
        std::cerr << "Error creating BIO from certificate data" << std::endl;
        return false;
    }

    // Read the X509 certificate from the BIO

    serverCert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!serverCert)
    {
        std::cerr << "Error reading X509 certificate from BIO" << std::endl;

        ERR_print_errors_fp(stderr); // Print OpenSSL error information
        BIO_free(bio);

        return false;
    }

    // Print serial number
    ASN1_INTEGER *serialNumber = X509_get_serialNumber(serverCert);
    BIGNUM *bnSerial = ASN1_INTEGER_to_BN(serialNumber, nullptr);
    char *serialHex = BN_bn2hex(bnSerial);

    cout << "Serial Number: " << serialHex << endl;
    OPENSSL_free(serialHex);
    BN_free(bnSerial);
    // Clean up
    BIO_free(bio);

    return true;
}

bool Client::verifyServerCertificate(X509 *caCert, X509_CRL *crl, X509 *serverCert)
{

    // Create a store and add the CA certificate and CRL to it
    X509_STORE *store = X509_STORE_new();
    X509_STORE_add_cert(store, caCert);
    X509_STORE_add_crl(store, crl);

    // Set the flags to check against the CRL
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);

    // Create a context and set the store
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, serverCert, nullptr);

    // Perform the verification
    int ret = X509_verify_cert(ctx);
    if (ret != 1)
    {
        fprintf(stderr, "Certificate verification failed\n");
        ERR_print_errors_fp(stderr);
    }
    else
    {
        printf("Certificate verification succeeded\n");
    }

    // Clean up
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    X509_free(caCert);
    X509_CRL_free(crl);

    return ret == 1;
}

void Client::performClientJob()
{
    if (!connectToServer())
    {
        return;
    }
    if (!sendUsername())
    {
        return;
    }
    if (!receiveServerResponse())
    {
        return;
    }

    // end login phase
}

Client::~Client()
{
    // Clean up resources, close the socket, etc.
    close(clientSocket);
}
