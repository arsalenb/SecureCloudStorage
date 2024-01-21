#include "download.h"
#include <vector>
#include <arpa/inet.h>
// ----------------------------------- DOWNLOAD M1 ------------------------------------

DownloadM1::DownloadM1() {}

DownloadM1::DownloadM1(string file_name)
{
    this->command_code = RequestCodes::DOWNLOAD_REQ;
    strncpy(this->file_name, file_name.c_str(), MAX::file_name + 1);
}

Buffer DownloadM1::serialize() const
{
    Buffer buff(MAX::initial_request_length);
    size_t position = 0;

    // insert the command code uint8_t (one byte) interpreted as unsigned char
    memcpy(buff.data(), &command_code, sizeof(uint8_t));
    position += sizeof(uint8_t);

    // insert the file string with a size of max of file name (50) +1
    unsigned char const *file_name_pointer = reinterpret_cast<unsigned char const *>(&file_name);
    memcpy(buff.data() + position, file_name_pointer, ((MAX::file_name + 1) * sizeof(char)));

    return buff;
}

void DownloadM1::deserialize(Buffer input)
{
    size_t position = 0;

    memcpy(&this->command_code, input.data(), sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(&this->file_name, input.data() + position, (MAX::file_name + 1) * sizeof(char));
}

int DownloadM1::getSize()
{
    int size = 0;

    size += sizeof(uint8_t);
    size += (MAX::file_name + 1) * sizeof(char);

    return size;
}

void DownloadM1::print() const
{
    cout << "---------- DOWNLOAD M1 ---------" << endl;
    cout << "FILE NAME: " << file_name << endl;
    cout << "--------------------------------" << endl;
}

// ----------------------------------- DOWNLOAD ACKNOWLEDGEMENT ------------------------------------

DownloadAck::DownloadAck() {}

DownloadAck::DownloadAck(uint8_t ack_code)
{
    this->command_code = RequestCodes::DOWNLOAD_REQ;
    this->file_size = 0;
    this->ack_code = ack_code;
}

DownloadAck::DownloadAck(uint8_t ack_code, uint32_t file_size)
{
    this->command_code = RequestCodes::DOWNLOAD_REQ;
    this->file_size = file_size;
    this->ack_code = ack_code;
}

Buffer DownloadAck::serialize() const
{
    Buffer buff(DownloadAck::getSize());
    size_t position = 0;

    memcpy(buff.data(), &command_code, sizeof(uint8_t));
    position += sizeof(uint8_t);

    // Convert file_size to network byte order
    uint32_t no_file_size = htonl(file_size);

    // Insert file_size into the buffer
    unsigned char const *file_size_begin = reinterpret_cast<unsigned char const *>(&no_file_size);
    memcpy(buff.data() + position, file_size_begin, sizeof(uint32_t));
    position += sizeof(uint32_t);

    // Insert ack_code into the buffer
    memcpy(buff.data() + position, &ack_code, sizeof(uint8_t));

    return buff;
}

void DownloadAck::deserialize(Buffer input)
{

    size_t position = 0;

    // Extract command_code from the buffer
    memcpy(&this->command_code, input.data(), sizeof(uint8_t));
    position += sizeof(uint8_t);

    // Extract file_size from the buffer
    uint32_t network_filesize = 0;
    memcpy(&network_filesize, input.data() + position, sizeof(uint32_t));
    file_size = ntohl(network_filesize);
    position += sizeof(uint32_t);

    // Extract ack_code from the buffer
    memcpy(&this->ack_code, input.data() + position, sizeof(uint8_t));
}

int DownloadAck::getSize()
{
    int size = 0;

    size += sizeof(uint8_t);
    size += sizeof(uint32_t); // file_size
    size += sizeof(uint8_t);

    return size;
}

void DownloadAck::print() const
{
    cout << "---------- DOWNLOAD ACKNOWLEDGEMENT ---------" << endl;
    cout << "Acknowledge message: " << ack_code << endl;
    cout << "--------------------------------------------" << endl;
}

// ---------------------------------- DOWNLOAD M2 -----------------------------------

DownloadM2::DownloadM2(){};

DownloadM2::DownloadM2(Buffer file_chunk)
{
    command_code = RequestCodes::DOWNLOAD_CHUNK;
    this->file_chunk = file_chunk;
}

Buffer DownloadM2::serialize() const
{
    size_t chunk_size = file_chunk.size();
    Buffer buff(DownloadM2::getSize(chunk_size));

    size_t position = 0;

    memcpy(buff.data(), &command_code, sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(buff.data() + position, file_chunk.data(), chunk_size * sizeof(unsigned char));
    position += chunk_size * sizeof(unsigned char);

    return buff;
}

void DownloadM2::deserialize(Buffer input)
{
    size_t chunk_size = input.size() - sizeof(uint8_t);
    this->file_chunk = Buffer(chunk_size);

    size_t position = 0;

    memcpy(&this->command_code, input.data(), sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(this->file_chunk.data(), input.data() + position, chunk_size * sizeof(unsigned char));
}

size_t DownloadM2::getSize(size_t chunk_size)
{
    int size = 0;

    size += sizeof(uint8_t);
    size += chunk_size * sizeof(unsigned char);

    return size;
}

void DownloadM2::print() const
{
    cout << "--------- DOWNLOAD M2 --------" << endl;
    cout << "File chunk: ";
    for (Buffer::const_iterator it = file_chunk.begin(); it < file_chunk.end(); ++it)
        printf("%02X", *it);
    cout << "\nCHUNK SIZE: " << file_chunk.size() << endl;
    cout << "------------------------------" << endl;
}
