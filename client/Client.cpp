#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <limits>
#include "../security/Util.h"
#include "../security/crypto.h"
#include "../security/Diffie-Hellman.h"
#include "../packets/constants.h"
#include "Client.h"

#include "../tools/file.h"
#include "../packets/upload.h"
#include "../packets/wrapper.h"
#include "../packets/download.h"
#include "../packets/list.h"
#include "../packets/rename.h"
#include "../packets/delete.h"
#include "../packets/logout.h"

using namespace std;

enum class MenuOption
{
    UploadFile = 1,
    DownloadFile,
    ListFiles,
    RenameFile,
    DeleteFile,
    Logout
};

Client::Client() {}

int Client::login()
{
    // Initialize members and create a socket
    communcation_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (communcation_socket == -1)
    {
        std::cerr << "[LOGIN] Error creating client socket" << std::endl;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(ServerDetails::PORT);
    if (inet_pton(AF_INET, ServerDetails::SERVER_IP.c_str(), &serverAddr.sin_addr) <= 0)
    {
        std::cerr << "[LOGIN] Invalid address/Address not supported" << std::endl;
        return 0;
    }

    if (connect(communcation_socket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
        std::cerr << "[LOGIN] Error connecting to server" << std::endl;
        return 0;
    }

    std::cout << "[LOGIN] Enter your username (up to " + to_string(MAX::username_length) + " characters): ";
    std::getline(std::cin, username);

    // make sure input was valid and non null
    if (!cin || username.empty() || username.length() > MAX::username_length)
    {
        cerr << "[LOGIN] Invalid username input" << endl;
        return 0;
    }

    // Send username size to the server
    if (!sendSize(communcation_socket, username.size()))
    {
        std::cerr << "[LOGIN] Error sending the username length" << std::endl;
        return 0;
    }

    // Convert the username string to a vector of unsigned char
    Buffer usernameData(username.begin(), username.end());

    // Call sendData with the username data
    if (!sendData(communcation_socket, usernameData))
    {
        std::cerr << "[LOGIN] Error sending username to server" << std::endl;
        return 0;
    }
    size_t server_response;
    if (!receiveSize(communcation_socket, server_response))
    {
        // Handle the error if receiving data fails
        cerr << "[LOGIN] Error receiving the response from server" << endl;
        return 0;
    }

    // Implement the logic to handle the server response

    if (server_response == 0)
    {
        std::cerr << "[LOGIN] User does not exist" << std::endl;
        return 0;
    }
    // User exists, read the password of private key of the user

    // Read password from console
    std::cout << "[LOGIN] Enter the password of the private key: " << endl;
    std::getline(std::cin, password);

    // make sure input was valid and non null
    if (!cin || password.empty() || password.length() > MAX::passowrd_length)
    {
        cerr << "[LOGIN] Invalid password input" << endl;
        return 0;
    }
    // read user private key
    std::string privateKeyPath = "../commons/" + username + "/key.pem";
    EVP_PKEY *prvkey = nullptr;

    if (!loadPrivateKey(privateKeyPath, prvkey, password))
    {
        std::cerr << "[LOGIN] Invalid password for the private key" << std::endl;
        EVP_PKEY_free(prvkey);
        return 0;
    }

    // Generate the elliptic curve diffie-Hellman keys for the client
    EVP_PKEY *ECDH_client;
    if (!(ECDH_client = ECDHKeyGeneration()))
    {
        cerr << "[LOGIN] ECDH key generation failed" << endl;
        EVP_PKEY_free(ECDH_client);
        EVP_PKEY_free(prvkey);
        return 0;
    }

    Buffer sClientKey;

    if (!serializePubKey(ECDH_client, sClientKey))
    {
        cerr << "[LOGIN] Serialization of public key failed" << endl;
        EVP_PKEY_free(ECDH_client);
        EVP_PKEY_free(prvkey);
        return 0;
    }

    // Send the key size to the server
    size_t sClientKeyLength = sClientKey.size();
    if (!sendSize(communcation_socket, sClientKeyLength))
    {
        std::cerr << "[LOGIN] Error sending the client public key size to server" << std::endl;
        EVP_PKEY_free(ECDH_client);
        EVP_PKEY_free(prvkey);
        return 0;
    }
    // send the DH public key to the server
    if (!sendData(communcation_socket, sClientKey))
    {
        std::cerr << "[LOGIN] Error sending the client public key to server" << std::endl;
        EVP_PKEY_free(ECDH_client);
        EVP_PKEY_free(prvkey);
        return 0;
    }

    // receive from the server: (g^b) ,(g^b) size, {<(g^a,g^b)>s}k, IV

    size_t receiveBufferSize = calLengthLoginMessageFromTheServer();
    Buffer receiveBuffer;
    receiveBuffer.resize(receiveBufferSize);

    if (!receiveData(communcation_socket, receiveBuffer))
    {
        std::cerr << "[LOGIN] Error receiving [(g^b) ,(g^b) size, {<(g^a,g^b)>s}k, IV,Server_cert size, Server_cert] data from the server" << std::endl;
        EVP_PKEY_free(ECDH_client);
        EVP_PKEY_free(prvkey);
        return 0;
    }

    // Variables to store the deserialized components (g^b) ,(g^b) size, {<(g^a,g^b)>s}k, IV,Server_cert
    Buffer sServerEphemeralKey;
    Buffer certificate_buffer;
    int sServerEphemeralKeyLength = 0;
    Buffer cipher_text;
    Buffer iv;

    // Call the deserialize function
    if (!deserializeM3(receiveBuffer, sServerEphemeralKey, cipher_text, certificate_buffer, iv))
    {
        std::cerr << "[LOGIN] Error deseiralizing [(g^b) ,(g^b) size, {<(g^a,g^b)>s}k, IV, Server_cert size, Server_cert] " << std::endl;
        EVP_PKEY_free(ECDH_client);
        EVP_PKEY_free(prvkey);
        return 0;
    }

    // -------------------------- CERTIFICATE HANDLING ----------------------------------

    // User exists, proceed to receive the server certificate

    // Create a BIO from the received data
    BIO *bio = BIO_new_mem_buf(certificate_buffer.data(), certificate_buffer.size());
    if (!bio)
    {
        std::cerr << "[LOGIN] Error creating BIO from certificate data" << std::endl;
        EVP_PKEY_free(ECDH_client);
        EVP_PKEY_free(prvkey);
        return 0;
    }

    // Read the X509 certificate from the BIO
    X509 *server_cert = nullptr;

    server_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!server_cert)
    {
        std::cerr << "[LOGIN] Error reading X509 certificate from BIO" << std::endl;
        ERR_print_errors_fp(stderr);
        BIO_free(bio);
        EVP_PKEY_free(ECDH_client);
        EVP_PKEY_free(prvkey);
        return 0;
    }
    // Clean up
    BIO_free(bio);

    // Load CA certificate
    X509 *caCert = nullptr;
    FILE *caCertFilePtr = fopen(CryptoMaterials::caCertFile.c_str(), "r");
    if (!caCertFilePtr)
    {
        std::cerr << "[LOGIN] Error opening CA certificate file" << std::endl;
        EVP_PKEY_free(ECDH_client);
        EVP_PKEY_free(prvkey);
        return 0;
    }

    caCert = PEM_read_X509(caCertFilePtr, nullptr, nullptr, nullptr);
    fclose(caCertFilePtr);
    if (!caCert)
    {
        std::cerr << "[LOGIN] Error reading CA certificate file" << std::endl;
        EVP_PKEY_free(ECDH_client);
        EVP_PKEY_free(prvkey);
        X509_free(caCert);
        return 0;
    }

    // Load CRL
    X509_CRL *crl = nullptr;
    FILE *crlFilePtr = fopen(CryptoMaterials::crlFile.c_str(), "r");
    if (!crlFilePtr)
    {
        std::cerr << "[LOGIN] Error opening CLR  file" << std::endl;
        EVP_PKEY_free(ECDH_client);
        EVP_PKEY_free(prvkey);
        X509_free(caCert);
        return 0;
    }

    crl = PEM_read_X509_CRL(crlFilePtr, nullptr, nullptr, nullptr);
    fclose(crlFilePtr);

    if (!crl)
    {
        std::cerr << "[LOGIN] Error reading CLR  file" << std::endl;
        EVP_PKEY_free(ECDH_client);
        EVP_PKEY_free(prvkey);
        X509_free(caCert);
        X509_CRL_free(crl);
        return 0;
    }

    if (!verifyServerCertificate(caCert, crl, server_cert))
    {
        std::cerr << "[LOGIN] Server certificate verification failed." << std::endl;
        EVP_PKEY_free(ECDH_client);
        EVP_PKEY_free(prvkey);
        return 0;
    }

    // --------------------------------------------------------------------------------

    sServerEphemeralKeyLength = sServerEphemeralKey.size();
    if (sServerEphemeralKeyLength > Max_Ephemral_Public_Key_Size)
    {
        cerr << "[LOGIN] Ephemeral key size exceeds the max size" << std::endl;
        EVP_PKEY_free(ECDH_client);
        EVP_PKEY_free(prvkey);
        return 0;
    }

    EVP_PKEY *deserializedServerEphemeralKey = deserializePublicKey(sServerEphemeralKey);
    if (deserializedServerEphemeralKey == NULL)
    {
        cerr << "[LOGIN] Error deseiralizing the seerver ephemeral key" << std::endl;
        EVP_PKEY_free(ECDH_client);
        EVP_PKEY_free(prvkey);
        return 0;
    }

    // calculate (g^a)^b
    Buffer sharedSecretKey;
    size_t sharedSecretLength;

    if (deriveSharedSecret(ECDH_client, deserializedServerEphemeralKey, sharedSecretKey) == -1)
    {
        std::cerr << "[LOGIN] Key derivation was unsuccessfull" << std::endl;
        EVP_PKEY_free(ECDH_client);
        EVP_PKEY_free(prvkey);
        return 0;
    }
    // free ECDH_client
    EVP_PKEY_free(ECDH_client);

    sharedSecretLength = sharedSecretKey.size();
    // generate session key Sha256((g^a)^b)
    Buffer digest;

    if (!computeSHA256Digest(sharedSecretKey, digest))
    {
        std::cerr << "[LOGIN] Shared secret derivation failed" << std::endl;
        EVP_PKEY_free(prvkey);
        return 0;
    }
    // take first 128 of the the digest
    generateSessionKey(digest, session_key);

    // Concatinate (g^b,g^a), the serialized keys
    Buffer concatenatedKeys;
    concatenatedKeys.insert(concatenatedKeys.begin(), sServerEphemeralKey.begin(), sServerEphemeralKey.end());
    concatenatedKeys.insert(concatenatedKeys.end(), sClientKey.begin(), sClientKey.end());

    // decrypt  {<(g^a,g^b)>s}k  using the session key
    Buffer plaintext;
    if (!decryptTextAES(cipher_text, session_key, iv, plaintext))
    {
        std::cerr << "[LOGIN] Error decrypting {<(g^a,g^b)>c}k" << std::endl;
        EVP_PKEY_free(prvkey);
        return 0;
    }
    // verify the <(g^a,g^b)>s
    EVP_PKEY *server_public_key = X509_get_pubkey(server_cert);
    if (!verifyDigitalSignature(concatenatedKeys, plaintext, server_public_key))
    {
        std::cerr << "[LOGIN] Failed to verify digital signature" << std::endl;
        EVP_PKEY_free(prvkey);
        EVP_PKEY_free(server_public_key);
        return 0;
    }
    // free server_public_key
    EVP_PKEY_free(server_public_key);

    // free server certificate
    X509_free(server_cert);

    // create the digiatl signature <(g^a,g^b)>c using the client private key
    Buffer signature;
    if (!generateDigitalSignature(concatenatedKeys, prvkey, signature))
    {
        std::cerr << "[LOGIN] Creating Digital Signature failed" << std::endl;
        EVP_PKEY_free(prvkey);
        return 0;
    }
    // free the client private key
    EVP_PKEY_free(prvkey);

    // encrypt  {<(g^a,g^b)>c}k  using the session key
    cipher_text.clear();
    int cipher_size;
    iv.clear();
    if (!encryptTextAES(signature, session_key, cipher_text, iv))
    {
        std::cerr << "[LOGIN] Encrypting Digital Signature failed" << std::endl;
        return 0;
    }
    //  send to the server: {<(g^a,g^b)>c}k, IV
    Buffer sendBuffer;
    serializeM4(cipher_text, iv, sendBuffer);

    if (!sendData(communcation_socket, sendBuffer))
    {
        std::cerr << "[LOGIN] Error sending [{<(g^a,g^b)>c}k, IV] to the server" << std::endl;
        return 0;
    }

    // Cleanup OpenSSL (if not done already)
    EVP_cleanup();
    clear_vec(digest);

    return 1;
}

bool Client::receiveServerCertificate(X509 *&serverCert)
{
    // Implement the logic to receive the server certificate

    // Receive the certificate size
    size_t certSize;
    if (!receiveSize(communcation_socket, certSize))
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
    Buffer certBuffer(certSize);
    if (!receiveData(communcation_socket, certBuffer))
    {
        std::cerr << "Error receiving certificate data" << std::endl;
        return false;
    }

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
        std::cerr << "Certificate verification failed" << std::endl;
        ERR_print_errors_fp(stderr);
    }

    // Clean up
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    X509_free(caCert);
    X509_CRL_free(crl);

    return ret == 1;
}
int Client::start()
{

    const int LogoutOption = static_cast<int>(MenuOption::Logout);

    if (!login())
    {
        std::cerr << "[CLIENT] Login failed" << std::endl;
        return 0;
    }

    std::string choice;
    int result;

    do
    {
        // Display menu
        std::cout << "Choose an option:" << std::endl;
        std::cout << "1. Upload file\n2. Download file\n3. List files\n"
                     "4. Rename file\n5. Delete file\n6. Logout\n";

        // Get user input
        std::cout << "[CLIENT] Enter your choice: ";
        std::getline(std::cin, choice);

        // Handle menu choice
        result = handleMenuChoice(choice);

        if (result == -1)
        {
            std::cerr << "[WORKER] Exiting .... Replay Attack or Counter reached maximum value" << std::endl;
            // Close any necessary resources (e.g., communication_socket)
            exit(EXIT_FAILURE);
        }

    } while (std::stoi(choice) != LogoutOption);

    return 0;
}
int Client::upload_file()
{
    bool file_valid = false;
    File file;

    cout << "****************************************" << endl;
    cout << "*********     UPLOAD FILE      *********" << endl;
    cout << "****************************************" << endl;

    // Read file path from console
    std::cout << "[UPLOAD] Enter file path:" << endl;
    std::string file_path;
    std::getline(std::cin, file_path);

    // make sure input was valid and non null
    if (!cin || file_path.empty())
    {
        cerr << "[UPLOAD] Invalid file path input" << endl;
        std::cin.clear(); // put us back in 'normal' operation mode
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
    // open the file denoted in path
    try
    {
        file.read(file_path);
        file.displayFileInfo();
        file_valid = true; // break out of loop
    }
    catch (const std::exception &e)
    {
        std::cerr << "[UPLOAD] " << e.what() << std::endl;
        return 0;
    }

    // check if file is not empty
    if (file.getFileSize() == 0)
    {
        cerr << "[UPLOAD] Cannot upload empty files!" << endl;
        return 0;
    }

    // check if file size doesn't exceed 4GB
    if (file.getFileSize() >= MAX::max_file_size)
    {
        cerr << "[UPLOAD] File is too large!" << endl;
        return 0;
    }

    // Create Upload M1 type packet
    UploadM1 m1(file.get_file_name(), file.getFileSize());
    Buffer serializedPacket = m1.serialize();
    // Create on the M1 message the wrapper packet to be sent
    Wrapper m1_wrapper(session_key, s_counter, serializedPacket);
    Buffer serialized_packet = m1_wrapper.serialize();

    // Send wrapped packet to server
    if (!sendData(communcation_socket, serialized_packet))
    {
        std::cerr << "[UPLOAD] Error sending the serialized packet" << std::endl;
        return 0;
    }

    clear_vec(serialized_packet);
    s_counter = incrementCounter(s_counter);
    if (s_counter == -1)
    {
        std::cerr << "[UPLOAD] Counter reached maximum value" << std::endl;
        return -1;
    }

    // -------------- HANDLE ACK PACKET ---------------------
    Buffer ack_buffer(Wrapper::getSize(UploadAck::getSize()));
    if (!receiveData(communcation_socket, ack_buffer))
    {
        std::cerr << "[UPLOAD] Error receiving  data" << std::endl;
        return 0;
    }
    // deserialize to extract payload in plaintext
    Wrapper wrapped_packet(session_key);

    if (!wrapped_packet.deserialize(ack_buffer))
    {
        std::cerr << "[UPLOAD] Wrapper packet wasn't deserialized correctly!" << endl;
        return 0;
    }

    if (wrapped_packet.getCounter() != r_counter)
        return -1;

    r_counter = incrementCounter(r_counter);
    if (r_counter == -1)
    {
        std::cerr << "[UPLOAD] Counter reached maximum value" << std::endl;
        return -1;
    }

    UploadAck ack;
    ack.deserialize(wrapped_packet.getPayload());

    if (!ack.getAckCode())
    {
        std::cerr << "[UPLOAD] File already exists on the cloud!" << endl;
        return 0;
    }

    // -------------- HANDLE SENDING FILE CHUNKS ---------------------
    size_t chunk_size = MAX::max_file_chunk;
    int num_file_chunks = file.getFileSize() / chunk_size;
    int last_chunk_size = file.getFileSize() % chunk_size;
    UploadM2 m2_packet;
    Wrapper m2_wrapper;

    // Send chunks to server
    for (int i = 0; i < num_file_chunks; i++)
    {
        m2_packet = UploadM2(file.readChunk(chunk_size));

        m2_wrapper = Wrapper(session_key, s_counter, m2_packet.serialize());

        serialized_packet = m2_wrapper.serialize();
        if (!sendData(communcation_socket, serialized_packet))
        {
            std::cerr << "[UPLOAD] Error sending the serialized packet" << std::endl;
            return 0;
        }

        s_counter = incrementCounter(s_counter);
        if (s_counter == -1)
        {
            std::cerr << "[UPLOAD] Counter reached maximum value" << std::endl;
            return -1;
        }

        // Log upload progess
        cout << "[UPLOAD] Uploaded " << (i + 1) * chunk_size << "/" << file.getFileSize() << "Bytes" << endl;
    }
    // send remaining data in file (if there's any)
    if (last_chunk_size != 0)
    {
        m2_packet = UploadM2(file.readChunk(last_chunk_size));

        Wrapper m2_wrapper(session_key, s_counter, m2_packet.serialize());

        serialized_packet = m2_wrapper.serialize();
        if (!sendData(communcation_socket, serialized_packet))
        {
            std::cerr << "[UPLOAD] Error sending the serialized packet" << std::endl;
            return 0;
        }

        s_counter = incrementCounter(s_counter);
        if (s_counter == -1)
        {
            std::cerr << "[UPLOAD] Counter reached maximum value" << std::endl;
            return -1;
        }
    }

    cout << "[UPLOAD] Uploaded " << file.getFileSize() << "/" << file.getFileSize() << "Bytes" << endl;

    // -------------- HANDLE ACK PACKET ---------------------
    Buffer final_ack_buffer(Wrapper::getSize(UploadAck::getSize()));
    if (!receiveData(communcation_socket, final_ack_buffer))
    {
        std::cerr << "Error receiving data" << std::endl;
        return false;
    }
    // deserialize to extract payload in plaintext
    wrapped_packet = Wrapper(session_key);

    if (!wrapped_packet.deserialize(final_ack_buffer))
    {
        std::cerr << "[UPLOAD] Wrapper packet wasn't deserialized correctly!" << endl;
        return 0;
    }

    if (wrapped_packet.getCounter() != r_counter)
        return -1;

    r_counter = incrementCounter(r_counter);
    if (r_counter == -1)
    {
        std::cerr << "[UPLOAD] Counter reached maximum value" << std::endl;
        return -1;
    }

    ack = UploadAck();
    ack.deserialize(wrapped_packet.getPayload());

    if (!ack.getAckCode())
        std::cerr << "[UPLOAD] Uploading file " << file.get_file_name() << " has failed!" << std::endl;
    else
        std::cout << "[UPLOAD] " << file.get_file_name() << " uploaded successfully" << std::endl;

    cout << "********************************************" << endl;
    cout << "*********     End Upload File    *********" << endl;
    cout << "********************************************" << endl;
    return 1;
}
int Client::download_file()
{
    bool file_valid = false;

    cout << "****************************************" << endl;
    cout << "*********     Download File    *********" << endl;
    cout << "****************************************" << endl;

    // Read file path from console
    std::cout << "[Download] Enter file name:" << endl;
    std::string filename;
    std::getline(std::cin, filename);

    // make sure input was valid and non null
    if (!cin || filename.empty() || !File::isValidFileName(filename) || filename.size() > MAX::file_name)
    {
        cerr << "[Download] Invalid filename input" << endl;
        std::cin.clear(); // put us back in 'normal' operation mode
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return 0;
    }

    // Create Download M1 type packet
    DownloadM1 m1(filename);

    // Create on the M1 message the wrapper packet to be sent
    Wrapper m1_wrapper(session_key, s_counter, m1.serialize());

    // serialize M1 Wrapper packet
    Buffer serialized_packet = m1_wrapper.serialize();

    // send wrapped packet to server
    if (!sendData(communcation_socket, serialized_packet))
    {
        return false;
    }
    clear_vec(serialized_packet);

    // increment counter
    s_counter = incrementCounter(s_counter);
    if (s_counter == -1)
    {
        std::cerr << "[DOWNLOAD] Counter reached maximum value" << std::endl;
        return -1;
    }

    // -------------- HANDLE ACK PACKET ---------------------
    Buffer ack_buffer(Wrapper::getSize(DownloadAck::getSize()));
    if (!receiveData(communcation_socket, ack_buffer))
    {
        std::cerr << "[Download] Error receiving data" << std::endl;
        return 0;
    }
    // deserialize to extract payload in plaintext
    Wrapper wrapped_packet(session_key);

    if (!wrapped_packet.deserialize(ack_buffer))
    {
        std::cerr << "[DOWNLOAD] Wrapper packet wasn't deserialized correctly!" << endl;
        return 0;
    }

    if (wrapped_packet.getCounter() != r_counter)
        return -1;

    r_counter = incrementCounter(r_counter);
    if (r_counter == -1)
    {
        std::cerr << "[DOWNLOAD] Counter reached maximum value" << std::endl;
        return -1;
    }

    DownloadAck ack;
    ack.deserialize(wrapped_packet.getPayload());

    if (ack.getAckCode())
    {
        std::cerr << "[Download] File does not exist on the cloud!" << endl;
        return 0;
    }
    uint32_t file_size = ack.getFileSize();

    // -------------- HANDLE RECEIVING FILE CHUNKS ---------------------

    File file;
    size_t chunk_size = MAX::max_file_chunk;
    int num_file_chunks = file_size / chunk_size;
    int last_chunk_size = file_size % chunk_size;
    DownloadM2 m2_packet;
    Wrapper m2_wrapper;
    bool error_occured = false;

    // Create "downloads" folder if it doesn't exist
    string downloads_path = "../downloads";
    if (!(std::filesystem::exists(downloads_path) && std::filesystem::is_directory(downloads_path)))
    {
        if (!std::filesystem::create_directory(downloads_path))
            return 0;
    }

    try
    {
        file.create(downloads_path + "/" + (string)filename);
    }
    catch (const std::exception &e)
    {
        std::cerr << "[DOWNLOAD] " << e.what() << std::endl;
        error_occured = true;
    }

    // Receive chunks from server
    for (int i = 0; i < num_file_chunks; i++)
    {
        // receive Wrapper packet message
        Buffer message_buff(Wrapper::getSize(DownloadM2::getSize(chunk_size)));

        if (!receiveData(communcation_socket, message_buff))
        {
            std::cerr << "[Download] Error receiving data" << std::endl;
            error_occured = true;
            continue;
        }

        m2_wrapper = Wrapper(session_key);

        if (!m2_wrapper.deserialize(message_buff))
        {
            std::cerr << "[Download] Wrapper packet wasn't deserialized correctly!" << endl;
            error_occured = true;
            continue;
        }

        // Check counter otherwise exit
        if (m2_wrapper.getCounter() != r_counter)
            return -1;

        r_counter = incrementCounter(r_counter);
        if (r_counter == -1)
        {
            std::cerr << "[DOWNLOAD] Counter reached maximum value" << std::endl;
            return -1;
        }

        m2_packet = DownloadM2();
        m2_packet.deserialize(m2_wrapper.getPayload());

        if (!error_occured)
            file.writeChunk(m2_packet.getFileChunk());

        // Log receival progess
        if (!error_occured)
            cout << "[Download] Downloaded " << (i + 1) * chunk_size << "B/ " << file_size << "B" << endl;
    }

    // receive remaining data in file (if there's any)
    if (last_chunk_size != 0)
    {
        Buffer message_buff(Wrapper::getSize(DownloadM2::getSize(last_chunk_size)));

        if (!receiveData(communcation_socket, message_buff))
        {
            std::cerr << "[Download] Error receiving  data" << std::endl;
            error_occured = true;
            return 0;
        }

        m2_wrapper = Wrapper(session_key);

        if (!m2_wrapper.deserialize(message_buff))
        {
            std::cerr << "[Download] Wrapper packet wasn't deserialized correctly!" << endl;
            error_occured = true;
            return 0;
        }

        // Check counter otherwise exit
        if (m2_wrapper.getCounter() != r_counter)
            return -1;

        r_counter = incrementCounter(r_counter);
        if (r_counter == -1)
        {
            std::cerr << "[DOWNLOAD] Counter reached maximum value" << std::endl;
            return -1;
        }

        m2_packet = DownloadM2();
        m2_packet.deserialize(m2_wrapper.getPayload());

        if (!error_occured)
            file.writeChunk(m2_packet.getFileChunk());
    }
    if (!error_occured)
        cout << "[Download] Downloaded " << file_size << "B/ " << file_size << "B" << endl;

    // ----------------------------------------------------------------------------

    if (error_occured)
        std::cerr << "[Download] File wasn't downloaded correctly!" << endl;
    else
        cout << "[Download] File downloaded correctly! " << endl;

    cout << "********************************************" << endl;
    cout << "*********     End Download File    *********" << endl;
    cout << "********************************************" << endl;
    return 1;
}
int Client::list_files()
{
    bool file_valid = false;
    File file;

    cout << "****************************************" << endl;
    cout << "*********     List Files    *********" << endl;
    cout << "****************************************" << endl;

    // Create List M1 type packet
    ListM1 m1;

    Buffer serializedPacket = m1.serialize();
    // Create on the M1 message the wrapper packet to be sent
    Wrapper m1_wrapper(session_key, s_counter, serializedPacket);

    // serialize M1 Wrapper packet
    Buffer serialized_packet = m1_wrapper.serialize();

    // send wrapped packet to server
    if (!sendData(communcation_socket, serialized_packet))
    {
        std::cerr << "[LIST] Error sending data to the server" << std::endl;
        return 0;
    }
    clear_vec(serialized_packet);

    // increment counter
    s_counter = incrementCounter(s_counter);
    if (s_counter == -1)
    {
        std::cerr << "[LIST] Counter reached maximum value" << std::endl;
        return -1;
    }

    // -------------- HANDLE ACK PACKET ---------------------
    Buffer ack_buffer(Wrapper::getSize(ListM2::getSize()));
    if (!receiveData(communcation_socket, ack_buffer))
    {
        std::cerr << "[LIST] Error receiving  data" << std::endl;
        return 0;
    }
    // deserialize to extract payload in plaintext
    Wrapper wrapped_packet(session_key);

    if (!wrapped_packet.deserialize(ack_buffer))
    {
        std::cerr << "[LIST] Wrapper packet wasn't deserialized correctly!" << endl;
        return 0;
    }

    if (wrapped_packet.getCounter() != r_counter)
        return -1;

    // increment counter
    r_counter = incrementCounter(r_counter);
    if (r_counter == -1)
    {
        std::cerr << "[LIST] Counter reached maximum value" << std::endl;
        return -1;
    }

    ListM2 ack_size_packet;
    ack_size_packet.deserialize(wrapped_packet.getPayload());

    if (ack_size_packet.getAckCode() == 1)
    {
        std::cerr << "[LIST] Folder doe not exist on the cloud!" << endl;
        return 0;
    }

    uint32_t file_list_size = ack_size_packet.getFile_List_Size();

    // receive the list of files from the server

    ListM3 m3(file_list_size);

    Buffer list_buffer(Wrapper::getSize(m3.getSize()));
    if (!receiveData(communcation_socket, list_buffer))
    {
        std::cerr << "[LIST] Error receiving data" << std::endl;
        return 0;
    }

    // deserialize to extract payload in plaintext
    Wrapper m3_wrapper(session_key);

    if (!m3_wrapper.deserialize(list_buffer))
    {
        std::cerr << "[LIST] Wrapper packet wasn't deserialized correctly!" << endl;
        return 0;
    }

    if (m3_wrapper.getCounter() != r_counter)
        return -1;

    m3.deserialize(m3_wrapper.getPayload());
    std::string fileListData = m3.getFileListData();

    // print the file names
    std::istringstream ss(fileListData);

    // Temporary string to store each element
    std::string token;

    // Use std::getline to split the string by commas
    while (std::getline(ss, token, ','))
    {
        // Print the file name
        std::cout << token << std::endl;
    }

    // incrment the counter
    r_counter = incrementCounter(r_counter);
    if (r_counter == -1)
    {
        std::cerr << "[LIST] Counter reached maximum value" << std::endl;
        return -1;
    }
    cout << "****************************************" << endl;
    cout << "*********     End List Files    *********" << endl;
    cout << "****************************************" << endl;

    return 1;
}
int Client::rename_file()
{
    bool file_valid = false;
    File file;

    cout << "****************************************" << endl;
    cout << "*********     RENAME FILE      *********" << endl;
    cout << "****************************************" << endl;

    // Read file name from console
    std::cout << "[RENAME] Enter file name:" << endl;
    std::string file_name;
    std::getline(std::cin, file_name);

    // make sure input was valid and non null
    if (!cin || file_name.empty() || !File::isValidFileName(file_name) || file_name.size() > MAX::file_name)
    {
        cerr << "[RENAME] Invalid file name input" << endl;
        std::cin.clear(); // put us back in 'normal' operation mode
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return 0;
    }

    // Read file name from console
    std::cout << "[RENAME] Enter new file name:" << endl;
    std::string new_file_name;
    std::getline(std::cin, new_file_name);

    // make sure input was valid and non null
    if (!cin || new_file_name.empty() || !File::isValidFileName(new_file_name) || new_file_name.size() > MAX::file_name)
    {
        std::cerr << "[RENAME] Invalid new file name input" << std::endl;
        std::cin.clear(); // put us back in 'normal' operation mode
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return 0;
    }

    // Create Rename M1 type packet
    RenameM1 m1(file_name, new_file_name);

    Buffer serializedPacket = m1.serialize();

    // Create on the M1 message the wrapper packet to be sent
    Wrapper m1_wrapper(session_key, s_counter, serializedPacket);

    Buffer serialized_packet = m1_wrapper.serialize();

    // Send wrapped packet to server
    if (!sendData(communcation_socket, serialized_packet))
    {
        std::cerr << "[RENAME] Error sending data" << std::endl;
        return 0;
    }

    clear_vec(serialized_packet);
    s_counter = incrementCounter(s_counter);
    if (s_counter == -1)
    {
        std::cerr << "[RENAME] Counter reached maximum value" << std::endl;
        return -1;
    }

    // -------------- HANDLE ACK PACKET ---------------------
    Buffer ack_buffer(Wrapper::getSize(RenameAck::getSize()));
    if (!receiveData(communcation_socket, ack_buffer))
    {
        std::cerr << "[RENAME] Error receiving  data" << std::endl;
        return 0;
    }
    // deserialize to extract payload in plaintext
    Wrapper wrapped_packet(session_key);

    if (!wrapped_packet.deserialize(ack_buffer))
    {
        std::cerr << "[RENAME] Wrapper packet wasn't deserialized correctly!" << endl;
        return 0;
    }

    if (wrapped_packet.getCounter() != r_counter)
    {
        return -1;
    }

    r_counter = incrementCounter(r_counter);
    if (r_counter == -1)
    {
        std::cerr << "[RENAME] Counter reached maximum value" << std::endl;
        return -1;
    }

    RenameAck ack;
    ack.deserialize(wrapped_packet.getPayload());

    if (ack.getAckCode() == 0)
    {
        std::cout << "[RENAME] File renamed successfully on the cloud!" << endl;
        return 1;
    }
    else if (ack.getAckCode() == 1)
    {
        std::cerr << "[RENAME] File rename failed on the cloud!" << endl;
        return 0;
    }
    if (ack.getAckCode() == 2)
    {
        std::cerr << "[RENAME] File does not exist on the cloud!" << endl;
        return 0;
    }
    cout << "****************************************" << endl;
    cout << "********     End Rename File    ********" << endl;
    cout << "****************************************" << endl;

    return 1;
}
int Client::delete_file()
{
    bool file_valid = false;
    File file;

    cout << "****************************************" << endl;
    cout << "*********     DELETE FILE      *********" << endl;
    cout << "****************************************" << endl;

    // Read file name from console
    std::cout << "[DELETE] Enter file name:" << endl;
    std::string file_name;
    std::getline(std::cin, file_name);

    // make sure input was valid and non null
    if (!cin || file_name.empty() || !File::isValidFileName(file_name) || file_name.size() > MAX::file_name)
    {
        cerr << "[DELETE] Invalid file name input" << endl;
        std::cin.clear(); // put us back in 'normal' operation mode
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return 0;
    }

    // Create Delete M1 type packet
    DeleteM1 m1(file_name);

    m1.print();
    Buffer serializedPacket = m1.serialize();

    // Create on the M1 message the wrapper packet to be sent
    Wrapper m1_wrapper(session_key, s_counter, serializedPacket);
    Buffer serialized_packet = m1_wrapper.serialize();

    // Send wrapped packet to server
    if (!sendData(communcation_socket, serialized_packet))
    {
        std::cerr << "[DELETE] Error sending the result to the server" << std::endl;
        return 0;
    }

    clear_vec(serialized_packet);
    s_counter = incrementCounter(s_counter);
    if (s_counter == -1)
    {
        std::cerr << "[DELETE] Counter reached maximum value" << std::endl;
        return -1;
    }

    // -------------- HANDLE ACK PACKET ---------------------
    Buffer ack_buffer(Wrapper::getSize(DeleteAck::getSize()));
    if (!receiveData(communcation_socket, ack_buffer))
    {
        std::cerr << "[DELETE] Error receiving  data" << std::endl;
        return 0;
    }
    // deserialize to extract payload in plaintext
    Wrapper wrapped_packet(session_key);

    if (!wrapped_packet.deserialize(ack_buffer))
    {
        std::cerr << "[DELETE] Wrapper packet wasn't deserialized correctly!" << endl;
        return 0;
    }

    if (wrapped_packet.getCounter() != r_counter)
        return -1;

    r_counter = incrementCounter(r_counter);
    if (r_counter == -1)
    {
        std::cerr << "[DELETE] Counter reached maximum value" << std::endl;
        return -1;
    }

    DeleteAck ack;
    ack.deserialize(wrapped_packet.getPayload());

    if (ack.getAckCode() == 0)
    {
        std::cout << "[DELETE] File deleted successfully on the cloud!" << endl;
        return 1;
    }
    else if (ack.getAckCode() == 1)
    {
        std::cerr << "[DELETE] File deletion failed on the cloud!" << endl;
        return 0;
    }
    if (ack.getAckCode() == 2)
    {
        std::cerr << "[CLIENT] File does not exist on the cloud!" << endl;
        return 0;
    }

    cout << "****************************************" << endl;
    cout << "********     End Delete File    ********" << endl;
    cout << "****************************************" << endl;

    return 1;
}
int Client::logout()
{
    LogoutM1 m1;

    Wrapper m1_wrapper(session_key, s_counter, m1.serialize());

    Buffer serialized_packet = m1_wrapper.serialize();

    // Send wrapped packet to server
    if (!sendData(communcation_socket, serialized_packet))
    {
        std::cerr << "[LOGOUT] Error sending the serialized packet" << std::endl;
        return 0;
    }

    clear_vec(serialized_packet);
    s_counter = incrementCounter(s_counter);
    if (s_counter == -1)
    {
        std::cerr << "[UPLOAD] Counter reached maximum value" << std::endl;
        return -1;
    }

    cout << "****************************************" << endl;
    cout << "***********   End Session   ************" << endl;
    cout << "****************************************" << endl;
    return 1;
}
int Client::handleMenuChoice(const std::string &choice)
{
    try
    {
        auto option = static_cast<MenuOption>(std::stoi(choice));
        switch (option)
        {
        case MenuOption::UploadFile:
            return upload_file();
        case MenuOption::DownloadFile:
            return download_file();
        case MenuOption::ListFiles:
            return list_files();
        case MenuOption::RenameFile:
            return rename_file();
        case MenuOption::DeleteFile:
            return delete_file();
        case MenuOption::Logout:
            return logout();
        default:
            std::cout << "Invalid choice. Please try again." << std::endl;
            return 0; // Indicate that no action was taken for invalid input
        }
    }
    catch (const std::invalid_argument &)
    {
        std::cout << "Invalid input. Please enter a number." << std::endl;
    }
    catch (const std::out_of_range &)
    {
        std::cout << "Invalid input. Number out of range." << std::endl;
    }
    return 0; // Indicate that no action was taken for invalid input
}

Client::~Client()
{
    // Clean up resources, close the socket, etc.
    close(communcation_socket);
    clear_vec(session_key);

    std::cout << "[CLIENT] CLIENT on socket : " << communcation_socket << " closed!" << std::endl;
}
