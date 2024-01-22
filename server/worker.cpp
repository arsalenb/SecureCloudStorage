#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <vector>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <algorithm>

#include "../security/Util.h"
#include "../security/crypto.h"
#include "../packets/upload.h"
#include "../packets/wrapper.h"
#include "../tools/file.h"
#include "download.h"
#include "list.h"
#include "rename.h"
#include "delete.h"
#include "worker.h"
#include <filesystem>
#include "logout.h"

typedef std::vector<unsigned char> Buffer;

Worker::Worker(int communcation_socket)
{
    this->communcation_socket = communcation_socket;
    cout << "[WORKER] Worker Initiated" << std::endl;
}
int Worker::login()
{

    size_t username_length;

    if (!receiveSize(communcation_socket, username_length))
    {
        cerr << "[LOGIN] Error receiving username length from client" << endl;
        return 0;
    }
    if (username_length > MAX::username_length)
    {
        std::cerr << "[LOGIN] Error: Username is too long. Maximum length is" + std::to_string(MAX::username_length) + " characters." << std::endl;
        return 0;
    }

    Buffer buffer(username_length);

    if (!receiveData(communcation_socket, buffer))
    {
        cerr << "[LOGIN] Error receiving username from client" << endl;
        return 0;
    }

    std::string received_username(buffer.begin(), buffer.end());
    username = received_username;
    std::cout << "[LOGIN] Received username from client: " << received_username << std::endl;

    // Check if username exists
    bool username_exists = false;

    for (const auto &user : username_list)
    {
        if (received_username == user)
        {
            username_exists = true;
            break;
        }
    }

    // Send result back to client
    size_t result = (username_exists) ? 1 : 0;

    if (!sendSize(communcation_socket, result))
    {
        std::cerr << "[LOGIN] Error sending the result to the client" << std::endl;
        return 0;
    }

    if (username_exists)
    {
        // Load the server certificate from PEM file
        FILE *server_certificate_file = fopen("../commons/Cloud_Storage_Server_cert.pem", "r");
        if (!server_certificate_file)
        {
            std::cerr << "[LOGIN] Error loading server certificate" << std::endl;
            return 0;
        }

        X509 *server_certif = PEM_read_X509(server_certificate_file, NULL, NULL, NULL);
        fclose(server_certificate_file);

        if (!server_certif)
        {
            std::cerr << "[LOGIN] Error reading server certificate" << std::endl;
            return 0;
        }

        // Send server certificate to client
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio)
        {
            std::cerr << "[LOGIN] Error creating BIO" << std::endl;
            X509_free(server_certif);
            return 0;
        }

        int result = PEM_write_bio_X509(bio, server_certif);

        if (!result)
        {
            std::cerr << "[LOGIN] (CertificateStore) Failed to write the certificate in the BIO" << std::endl;
            BIO_free(bio);
            return 0;
        }

        // Determine the size of the certificate
        int certif_size = BIO_pending(bio);

        // Resize the vector to fit the certificate
        Buffer certif_buffer(certif_size);
        if (BIO_read(bio, certif_buffer.data(), certif_size) <= 0)
        {
            std::cerr << "[LOGIN] (CertificateStore) Failed to read the certificate from the BIO" << std::endl;
            return 0;
        }

        BIO_free(bio);

        // Send the certificate size to the client
        if (!sendSize(communcation_socket, certif_size))
        {
            std::cerr << "[LOGIN] Error sending the certificate size" << std::endl;
            return 0;
        }

        // Send the certificate data to the client
        if (!sendData(communcation_socket, certif_buffer))
        {
            std::cerr << "[LOGIN] Error while sending the certificate to client" << std::endl;
            return 0;
        }

        // receive the client ECDH public key
        EVP_PKEY *deserializedClientKey;
        Buffer sClientKey;

        if (!receiveEphemeralPublicKey(communcation_socket, deserializedClientKey, sClientKey))
        {
            // Handle the case where receiving or deserialization failed
            std::cerr << "Failed to receive or deserialize the key" << std::endl;
            return 0;
        }

        // Generate the elliptic curve diffie-Hellman key pair of server
        EVP_PKEY *ECDH_server;
        if (!(ECDH_server = ECDHKeyGeneration()))
        {
            std::cerr << "[LOGIN] ECDH key generation failed" << std::endl;
            return 0;
        }

        // Serialize the public key
        Buffer sServerKey;

        if (!serializePubKey(ECDH_server, sServerKey))
        {
            std::cerr << "[LOGIN] Serialization of public key failed" << std::endl;
            return 0;
        }

        // Calculate (g^a)^b
        Buffer sharedSecretKey;
        int derivationResult = deriveSharedSecret(ECDH_server, deserializedClientKey, sharedSecretKey);
        if (!derivationResult)
        {
            std::cerr << "[LOGIN] Key derivation was unsuccessfull" << std::endl;
            return 0;
        }

        // Generate session key Sha256((g^a)^b)
        Buffer digest;
        if (!computeSHA256Digest(sharedSecretKey, digest))
        {
            std::cerr << "[LOGIN] Shared secret derivation failed" << std::endl;
            return 0;
        }

        // Extract first 128bits of the digest
        generateSessionKey(digest, session_key);

        // Concatinate (g^b,g^a), the serialized keys
        Buffer concatenatedKeys;
        concatenatedKeys.insert(concatenatedKeys.begin(), sServerKey.begin(), sServerKey.end());
        concatenatedKeys.insert(concatenatedKeys.end(), sClientKey.begin(), sClientKey.end());

        // Load server private key:
        EVP_PKEY *server_private_key = nullptr;
        string pem_pass = "root";
        if (!loadPrivateKey("../commons/server_private_key.pem", server_private_key, pem_pass))
        {
            std::cerr << "[LOGIN] Loading Server Private Key failed" << std::endl;
            return 0;
        }

        // Create the digiatl signature <(g^a,g^b)>s using the server private key
        Buffer signature;
        if (!generateDigitalSignature(concatenatedKeys, server_private_key, signature))
        {
            std::cerr << "[LOGIN] Creating Digital Signature failed" << std::endl;
            return 0;
        }
        EVP_PKEY_free(server_private_key);

        // Encrypt  {<(g^a,g^b)>s}k  using the session key
        Buffer cipher_text;
        Buffer iv;

        if (!encryptTextAES(signature, session_key, cipher_text, iv))
        {
            std::cerr << "[LOGIN] Encrypting Digital Signature failed" << std::endl;
            return 0;
        }
        // Send to the client: (g^b) ,(g^b) size, {<(g^a,g^b)>s}k, IV

        Buffer sendBuffer;

        serializeLoginMessageFromTheServer(sServerKey, cipher_text, iv, sendBuffer);

        if (!sendData(communcation_socket, sendBuffer))
        {
            std::cerr << "[LOGIN] Sending [(g^b) ,(g^b) size, {<(g^a,g^b)>s}k, IV] failed" << std::endl;
            return 0;
        }

        // Receive from the client:  {<(g^a,g^b)>c}k, IV

        size_t receive_buffer_size = Encrypted_Signature_Size + CBC_IV_Length;

        Buffer receive_buffer(receive_buffer_size);
        if (!receiveData(communcation_socket, receive_buffer))
        {
            std::cerr << "[LOGIN] Error receiving {<(g^a,g^b)>c}k, IV" << std::endl;
            return 0;
        }

        // Variables to store the deserialized components {<(g^a,g^b)>c}k, IV
        clear_vec(cipher_text);
        clear_vec(iv);

        // Call the deserialize function
        deserializeLoginMessageFromTheClient(receive_buffer, cipher_text, iv);

        // Decrypt  {<(g^a,g^b)>c}k  using the session key
        Buffer plaintext;
        if (!decryptTextAES(cipher_text, session_key, iv, plaintext))
        {
            std::cerr << "[LOGIN] Error decrypting {<(g^a,g^b)>c}k" << std::endl;
            return 0;
        }

        // Load user public key
        std::string public_key_path = "../commons/" + username + "/public.pem";
        EVP_PKEY *client_public_key = nullptr;
        if (!loadPublicKey(public_key_path, client_public_key))
        {
            std::cerr << "[LOGIN] Failed to load user public key" << std::endl;
            return 0;
        }

        if (!verifyDigitalSignature(concatenatedKeys, plaintext, client_public_key))
        {
            std::cerr << "[LOGIN] Failed to verify digital signature" << std::endl;
            return 0;
        }

        std::cout << "[LOGIN] Login Success" << std::endl;
        return 1;
    }
    else
    {
        return 0;
    }
}
int Worker::upload_file(Buffer payload)
{
    // ------ HERE WE START THE UPLOAD ROUTINE -----

    // Deserialize m1 general packet
    UploadM1 m1;
    m1.deserialize(payload);
    Buffer serialized_packet;

    // Check if the file exists
    string file_path = "../data/" + username + "/" + (string)m1.file_name;
    UploadAck ack_packet;

    if (File::exists(file_path))
        ack_packet = UploadAck(0);
    else
        ack_packet = UploadAck(1);

    Wrapper ack_wrapper(session_key, s_counter, ack_packet.serialize());

    serialized_packet = ack_wrapper.serialize();

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
    // -------------- HANDLE SENDING FILE CHUNKS ---------------------
    size_t chunk_size = MAX::max_file_chunk;
    int num_file_chunks = m1.file_size / chunk_size;
    int last_chunk_size = m1.file_size % chunk_size;
    UploadM2 m2_packet;
    Wrapper m2_wrapper;
    bool error_occured = false;

    File file;
    file.create(file_path);

    // Receive chunks from client
    for (int i = 0; i < num_file_chunks; i++)
    {
        // receive Wrapper packet message
        Buffer message_buff(Wrapper::getSize(UploadM2::getSize(chunk_size)));

        if (!receiveData(communcation_socket, message_buff))
        {
            std::cerr << "[UPLOAD] Error receiving  data" << std::endl;
            error_occured = true;
            continue;
        }

        m2_wrapper = Wrapper(session_key);

        if (!m2_wrapper.deserialize(message_buff))
        {
            std::cerr << "[UPLOAD] Wrapper packet wasn't deserialized correctly!" << endl;
            error_occured = true;
            continue;
        }

        // Check counter otherwise exit
        if (m2_wrapper.getCounter() != r_counter)
            return -1;

        // Increment Counter
        r_counter = incrementCounter(r_counter);
        if (r_counter == -1)
        {
            std::cerr << "[UPLOAD] Counter reached maximum value" << std::endl;
            return -1;
        }

        m2_packet = UploadM2();
        m2_packet.deserialize(m2_wrapper.getPayload());

        file.writeChunk(m2_packet.getFileChunk());

        // Log receival progess
        cout << "[UPLOAD] Received " << (i + 1) * chunk_size << "B/ " << m1.file_size << "B" << endl;
    }

    // receive remaining data in file (if there's any)
    if (last_chunk_size != 0)
    {
        Buffer message_buff(Wrapper::getSize(UploadM2::getSize(last_chunk_size)));

        if (!receiveData(communcation_socket, message_buff))
        {
            std::cerr << "Error receiving  data" << std::endl;
            error_occured = true;
            return 0;
        }

        m2_wrapper = Wrapper(session_key);

        if (!m2_wrapper.deserialize(message_buff))
        {
            std::cerr << "[UPLOAD] Wrapper packet wasn't deserialized correctly!" << endl;
            error_occured = true;
            return 0;
        }

        // Check counter otherwise exit
        if (m2_wrapper.getCounter() != r_counter)
            return -1;

        r_counter = incrementCounter(r_counter);
        if (r_counter == -1)
        {
            std::cerr << "[UPLOAD] Counter reached maximum value" << std::endl;
            return -1;
        }

        m2_packet = UploadM2();
        m2_packet.deserialize(m2_wrapper.getPayload());

        file.writeChunk(m2_packet.getFileChunk());
    }
    cout << "[UPLOAD] Received " << m1.file_size << "B/ " << m1.file_size << "B" << endl;

    // -------------- HANDLE ACK PACKET ---------------------

    if (error_occured)
        ack_packet = UploadAck(0); // in case of error

    else
        ack_packet = UploadAck(1);

    ack_wrapper = Wrapper(session_key, s_counter, ack_packet.serialize());

    serialized_packet = ack_wrapper.serialize();
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

    return 1;
}
int Worker::download_file(Buffer payload)
{

    // Deserialize m1 general packet
    DownloadM1 m1;
    m1.deserialize(payload);
    Buffer serialized_packet;

    // Check if the file exists
    string file_path = "../data/" + username + "/" + (string)m1.file_name;
    File file;
    bool file_error = false;

    // Try to open the file denoted in path
    try
    {
        file.read(file_path);

        // check if file is not empty
        if (file.getFileSize() == 0)
        {
            cerr << "[DOWNLOAD] Cannot download empty files!" << endl;
            file_error = true;
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "[DOWNLOAD] " << e.what() << std::endl;
        file_error = true;
    }

    DownloadAck ack_packet;

    if (!file_error)
        ack_packet = DownloadAck(0, file.getFileSize());
    else
        ack_packet = DownloadAck(1);

    Wrapper ack_wrapper(session_key, s_counter, ack_packet.serialize());

    serialized_packet = ack_wrapper.serialize();
    if (!sendData(communcation_socket, serialized_packet))
    {
        std::cerr << "Error sending the serialized packet" << std::endl;
        return 0;
    }

    s_counter = incrementCounter(s_counter);
    if (s_counter == -1)
    {
        std::cerr << "[DOWLOAD] Counter reached maximum value" << std::endl;
        return -1;
    }

    // -------------- HANDLE SENDING FILE CHUNKS ---------------------
    size_t chunk_size = MAX::max_file_chunk;
    int num_file_chunks = file.getFileSize() / chunk_size;
    int last_chunk_size = file.getFileSize() % chunk_size;
    DownloadM2 m2_packet;
    Wrapper m2_wrapper;

    // Send chunks to client
    for (int i = 0; i < num_file_chunks; i++)
    {
        m2_packet = DownloadM2(file.readChunk(chunk_size));

        m2_wrapper = Wrapper(session_key, s_counter, m2_packet.serialize());

        serialized_packet = m2_wrapper.serialize();
        if (!sendData(communcation_socket, serialized_packet))
            return 0;

        s_counter = incrementCounter(s_counter);
        if (s_counter == -1)
        {
            std::cerr << "[DOWNLOAD] Counter reached maximum value" << std::endl;
            return -1;
        }

        // Log upload progess
        cout << "[DOWNLOAD] Sent " << (i + 1) * chunk_size << "/" << file.getFileSize() << "Bytes" << endl;
    }
    // send remaining data in file (if there's any)
    if (last_chunk_size != 0)
    {
        m2_packet = DownloadM2(file.readChunk(last_chunk_size));

        Wrapper m2_wrapper(session_key, s_counter, m2_packet.serialize());

        serialized_packet = m2_wrapper.serialize();
        if (!sendData(communcation_socket, serialized_packet))
            return 0;

        s_counter = incrementCounter(s_counter);
        if (s_counter == -1)
        {
            std::cerr << "[DOWNLOAD] Counter reached maximum value" << std::endl;
            return -1;
        }
    }

    cout << "[DOWNLOAD] Sent " << file.getFileSize() << "/" << file.getFileSize() << "Bytes" << endl;
    return 1;
}
int Worker::list_files(Buffer payload)
{

    // ------ HERE WE START THE List ROUTINE -----

    // Deserialize m1 general packet
    ListM1 m1;
    m1.deserialize(payload);
    Buffer serialized_packet;

    ListM2 ack_size_packet;
    File file;
    uintmax_t file_size;
    string folder_path = "../data/" + username;
    string fileNames;

    if (std::filesystem::exists(folder_path) && std::filesystem::is_directory(folder_path))
    {

        try
        {
            fileNames = file.getFileNames(folder_path);
            ack_size_packet = ListM2(0, fileNames.length());
        }
        catch (const std::exception &e)
        {
            std::cerr << "[LIST] " << e.what() << std::endl;
            ack_size_packet = ListM2(1, 0); // error code : 1
        }
    }
    else
    {
        // folder does not exist
        ack_size_packet = ListM2(1, 0); // error code : 1
    }

    Wrapper ack_wrapper(session_key, s_counter, ack_size_packet.serialize());

    serialized_packet = ack_wrapper.serialize();
    if (!sendData(communcation_socket, serialized_packet))
    {
        std::cerr << "[LIST] Error sending the serialized packet" << std::endl;
        return 0;
    }

    s_counter = incrementCounter(s_counter);
    if (s_counter == -1)
    {
        std::cerr << "[LIST] Counter reached maximum value" << std::endl;
        return -1;
    }

    // send the list of files to the client

    ListM3 m3(fileNames.length());
    m3.setFileListData(fileNames.c_str());

    Wrapper wrapper(session_key, s_counter, m3.serialize());

    serialized_packet = wrapper.serialize();
    if (!sendData(communcation_socket, serialized_packet))
    {
        std::cerr << "[LIST] Error sending the serialized packet" << std::endl;
        return 0;
    }

    s_counter = incrementCounter(s_counter);
    if (s_counter == -1)
    {
        std::cerr << "[LIST] Counter reached maximum value" << std::endl;
        return -1;
    }
    return 1;
}
int Worker::rename_file(Buffer payload)
{

    // Deserialize m1 general packet
    RenameM1 m1;
    m1.deserialize(payload);
    Buffer serialized_packet;

    // Check if the file exists
    string file_name = (string)m1.file_name;
    string new_file_name = (string)m1.new_file_name;
    string file_path = "../data/" + username + "/" + file_name;
    string new_file_path = "../data/" + username + "/" + new_file_name;

    RenameAck ack_packet;
    File file;

    uintmax_t file_size;

    if (File::exists(file_path))
    {
        // check if there is already no file with the same new name
        if (!File::exists(new_file_path) && file.changeFileName(file_path, new_file_path) == 0)
        {

            ack_packet = RenameAck(0); // 0 means success
        }
        else
        {
            ack_packet = RenameAck(1); // error code : 1 means file rename failed
        }
    }
    else
    {
        // file does not exist
        ack_packet = RenameAck(2); // error code : 2 means the file does not exist
    }

    Wrapper ack_wrapper(session_key, s_counter, ack_packet.serialize());

    serialized_packet = ack_wrapper.serialize();
    if (!sendData(communcation_socket, serialized_packet))
    {
        std::cerr << "[RENAME] Error sending the serialized packet" << std::endl;
        return 0;
    }

    s_counter = incrementCounter(s_counter);
    if (s_counter == -1)
    {
        std::cerr << "[RENAME] Counter reached maximum value" << std::endl;
        return -1;
    }
    return 1;
}
int Worker::delete_file(Buffer payload)
{
    // ------ HERE WE START THE DELETE ROUTINE -----
    // Deserialize m1 general packet
    DeleteM1 m1;
    m1.deserialize(payload);
    Buffer serialized_packet;

    // Check if the file exists
    string file_name = (string)m1.file_name;
    string file_path = "../data/" + username + "/" + file_name;

    DeleteAck ack_packet;
    File file;

    uintmax_t file_size;

    if (File::exists(file_path))
    {
        // check if there is already no file with the same new name
        if (file.deleteFile(file_path) == 0)
        {

            ack_packet = DeleteAck(0); // 0 means success
        }
        else
        {
            ack_packet = DeleteAck(1); // error code : 1 means file deletion failed
        }
    }
    else
    {
        // file does not exist
        ack_packet = DeleteAck(2); // error code : 2 means the file does not exist
    }

    Wrapper ack_wrapper(session_key, s_counter, ack_packet.serialize());

    serialized_packet = ack_wrapper.serialize();
    if (!sendData(communcation_socket, serialized_packet))
    {
        std::cerr << "[DELETE] Error sending the serialized packet" << std::endl;
        return 0;
    }

    s_counter = incrementCounter(s_counter);
    if (s_counter == -1)
    {
        std::cerr << "[DELETE] Counter reached maximum value" << std::endl;
        return -1;
    }

    return 1;
}
int Worker::logout(Buffer payload)
{
    LogoutM1 m1;
    m1.deserialize(payload);
    // free hash and secret keys
    clear_vec(session_key);
    return 0;
}
int Worker::start()
{
    uint8_t command_code;

    // Inititiate login and key exchange routine
    if (!login())
    {
        std::cerr << "[WORKER] Login failed" << std::endl;
        return 0;
    }

    // If login is successfull await for commands from the client
    do
    {
        // receive Wrapper packet message
        Buffer message_buff(Wrapper::getSize(MAX::initial_request_length));

        if (!receiveData(communcation_socket, message_buff))
        {
            std::cerr << "[WORKER] Error receiving request" << std::endl;
            return 0;
        }
        // deserialize to extract payload in plaintext
        Wrapper wrapped_packet(session_key);

        if (!wrapped_packet.deserialize(message_buff))
        {
            std::cerr << "[WORKER] Wrapper packet wasn't deserialized correctly!" << endl;
            return 0;
        }

        // Extract command code from payload

        Buffer payload = wrapped_packet.getPayload();
        int packet_counter = wrapped_packet.getCounter();
        memcpy(&command_code, payload.data(), sizeof(uint8_t));

        // Check counter otherwise exit
        if (packet_counter != r_counter)
            return -1;

        r_counter = incrementCounter(r_counter);
        if (r_counter == -1)
        {
            std::cerr << "[WORKER] Counter reached maximum value" << std::endl;
            return -1;
        }

        // -------------- HANDLE COMMAND SELECTION ---------------------
        int result;
        switch (command_code)
        {
        case RequestCodes::UPLOAD_REQ:
            result = upload_file(payload);
            break;
        case RequestCodes::DOWNLOAD_REQ:
            result = download_file(payload);
            break;
        case RequestCodes::LIST_REQ:
            result = list_files(payload);
            break;
        case RequestCodes::RENAME_REQ:
            result = rename_file(payload);
            break;
        case RequestCodes::DELETE_REQ:
            result = delete_file(payload);
            break;
        case RequestCodes::LOGOUT_REQ:
            result = logout(payload);
            break;
        default:
            std::cerr << "[WORKER] Command not recognized" << std::endl;
            break;
        }

        if (result == -1)
        {
            std::cerr << "[WORKER] Exiting .... Replay Attack or Counter reached maximum value" << std::endl;
            close(communcation_socket);
            exit(EXIT_FAILURE);
        }

    } while (RequestCodes::LOGOUT_REQ != command_code);

    // Close communication socket with client and exit correctly
    close(communcation_socket);

    return 0;
}
Worker::~Worker()
{
    clear_vec(session_key);

    std::cout << "[WORKER] Worker on socket : " << communcation_socket << " closed!" << std::endl;
}