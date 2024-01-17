#include "crypto.h"
#include "wrapper.h"

namespace crypto2
{
    const EVP_CIPHER *cipher = EVP_aes_128_ccm();
    const int IV_LENGTH = EVP_CIPHER_iv_length(cipher);
    const int TAG_LENGTH = 14; // self-chosen to be on 14 bytes (valid sizes are: 4, 6, 10, 12, 14 and 16 bytes)
    const int BLOCK_SIZE = EVP_CIPHER_block_size(cipher);
    const int KEY_LEN = EVP_CIPHER_key_length(cipher);

}

Wrapper::Wrapper() {}

Wrapper::Wrapper(Buffer session_key)
{
    this->session_key = session_key;
};

Wrapper::Wrapper(Buffer session_key, int counter, Buffer payload)
{
    this->session_key = session_key;
    this->counter = counter;
    this->pt = payload;
}

// in case of error returns empty buffer
Buffer Wrapper::serialize()
{
    Buffer iv;
    Buffer aad;
    Buffer tag;
    Buffer packet;

    // Allocate buffer size and randomly generate IV
    if (!generateRandomValue(iv, crypto2::IV_LENGTH))
    {
        cerr << "[Wrapper_Serialize] Error occurred in generating IV\n";
        return Buffer(); // Return an empty buffer to indicate error
    }
    // Convert counter to network byte order
    int n_counter = htonl(counter);
    // Create AAD
    aad = createAAD(n_counter, iv);

    // encrypt using AES_CCM_128 the payload
    if (!encrypt_aes_ccm(pt, ct, session_key, iv, aad, tag))
    {
        cerr << "[Wrapper_Serialize] Encryption failed\n";
        return Buffer(); // Return an empty buffer to indicate error
    }

    // create wrapper packet: IV | Counter | CT | TAG
    packet.insert(packet.begin(), iv.begin(), iv.end()); // Add IV
    packet.insert(packet.end(), reinterpret_cast<char *>(&n_counter), reinterpret_cast<char *>(&n_counter) + sizeof(counter));
    packet.insert(packet.end(), ct.begin(), ct.end());   // Add CT
    packet.insert(packet.end(), tag.begin(), tag.end()); // Add TAG

    return packet;
};

int Wrapper::deserialize(Buffer wrapper)
{
    int n_counter;
    Buffer iv;
    Buffer aad;
    Buffer tag;

    size_t position = 0;

    // extract IV from wrapper packet
    iv.resize(crypto2::IV_LENGTH * sizeof(unsigned char));
    memcpy(iv.data(), wrapper.data(), crypto2::IV_LENGTH * sizeof(unsigned char));
    position += crypto2::IV_LENGTH * sizeof(unsigned char);

    // extract counter
    memcpy(&n_counter, wrapper.data() + position, sizeof(int));
    counter = ntohl(n_counter);
    position += sizeof(int);

    // extract cipher text and allocate space on buffer for it
    size_t ct_size = wrapper.size() - (((crypto2::IV_LENGTH + crypto2::TAG_LENGTH) * sizeof(unsigned char)) + sizeof(int));
    ct.resize(ct_size);
    memcpy(ct.data(), wrapper.data() + position, ct_size);
    position += ct_size;

    // extract TAG
    tag.resize(crypto2::TAG_LENGTH);
    memcpy(tag.data(), wrapper.data() + position, crypto2::TAG_LENGTH * sizeof(unsigned char));

    // Create AAD
    aad = createAAD(n_counter, iv);

    // decrypt using AES_CCM_128 the ciphertext
    if (!decrypt_aes_ccm(ct, pt, session_key, iv, aad, tag))
    {
        cerr << "[Wrapper_Deserialize] Decryption failed\n";
        return 0;
    }

    return 1;
}

Buffer Wrapper::createAAD(int counter, Buffer iv)
{
    Buffer aad;
    int n_counter;

    // insert IV in aad
    aad.insert(aad.begin(), iv.begin(), iv.end());

    // change host to network byte order of counter
    n_counter = htonl(counter);

    // set the counter_begin pointer on the int value
    unsigned char const *counter_begin = reinterpret_cast<unsigned char const *>(&n_counter);

    // insert counter into the buffer which is on int
    aad.insert(aad.end(), counter_begin, counter_begin + sizeof(int));

    return aad;
}

size_t Wrapper::getSize(size_t pt_size)
{
    size_t size = 0;

    size += crypto2::IV_LENGTH * sizeof(unsigned char);
    size += sizeof(int);
    size += pt_size * sizeof(unsigned char); // Cipher text size is equal to plaintext size since we are in AES_CCM (CTR streaming mode)
    size += crypto2::TAG_LENGTH * sizeof(unsigned char);

    return size;
}

void Wrapper::print() const
{
    cout << "---------- WRAPPER PACKET ---------" << endl;
    cout << "COUNTER: " << counter << endl;
    cout << "SESSION KEY: ";
    for (Buffer::const_iterator it = session_key.begin(); it < session_key.end(); ++it)
        printf("%02X", *it);
    cout << "\nPLAIN/CIPHER SIZE: " << pt.size() << endl;
    cout << "------------------------------" << endl;
}
