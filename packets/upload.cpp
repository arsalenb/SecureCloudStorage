#include "./upload.h"
#include <vector>
#include <arpa/inet.h>

// ----------------------------------- UPLOAD M1 ------------------------------------

UploadM1::UploadM1() {}
UploadM1::UploadM1(string file_name, uint32_t file_size)
{

    this->command_code = RequestCodes::UPLOAD_REQ;
    this->file_size = file_size;
    strncpy(this->file_name, file_name.c_str(), MAX::file_name + 1);
}

Buffer UploadM1::serialize() const
{
    Buffer buff(MAX::initial_request_length);
    uint32_t no_file_size; // network order file size

    size_t position = 0;

    // insert the command code unint8_t (one byte) interepreted as unsigned char
    memcpy(buff.data(), &command_code, sizeof(uint8_t));

    position += sizeof(uint8_t);

    // insert the file string which has a size of max of file name (50) +1
    unsigned char const *file_name_pointer = reinterpret_cast<unsigned char const *>(&file_name);
    memcpy(buff.data() + position, file_name_pointer, ((MAX::file_name + 1) * sizeof(char)));
    position += (MAX::file_name + 1) * sizeof(char);

    // change host to network byte order of file_size
    no_file_size = htonl(file_size);

    // set the file_size_begin pointer on the uint32_t value
    unsigned char const *file_size_begin = reinterpret_cast<unsigned char const *>(&no_file_size);

    // insert file size into the vector which is on uint32_t
    memcpy(buff.data() + position, file_size_begin, sizeof(uint32_t));

    return buff;
}

void UploadM1::deserialize(Buffer input)
{
    size_t position = 0;

    memcpy(&this->command_code, input.data(), sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(&this->file_name, input.data() + position, (MAX::file_name + 1) * sizeof(char));
    position += (MAX::file_name + 1) * sizeof(char);

    uint32_t network_filesize = 0;

    memcpy(&this->file_size, input.data() + position, sizeof(uint32_t));
    file_size = ntohl(file_size);
}

int UploadM1::getSize()
{

    int size = 0;

    size += sizeof(uint8_t);
    size += (MAX::file_name + 1) * sizeof(char);
    size += sizeof(uint32_t);

    return size;
}

void UploadM1::print() const
{
    cout << "---------- UPLOAD M1 ---------" << endl;
    cout << "FILE NAME: " << file_name << endl;
    cout << "FILE SIZE: " << file_size << endl;
    cout << "------------------------------" << endl;
}

// ----------------------------------- UPLOAD ACK ------------------------------------

UploadAck::UploadAck() {}
UploadAck::UploadAck(uint8_t ack_code)
{
    this->command_code = RequestCodes::UPLOAD_REQ;
    this->ack_code = ack_code;
}

Buffer UploadAck::serialize() const
{
    Buffer buff(UploadAck::getSize());
    size_t position = 0;

    memcpy(buff.data(), &command_code, sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(buff.data() + position, &ack_code, sizeof(uint8_t));
    position += sizeof(uint8_t);

    return buff;
}

void UploadAck::deserialize(Buffer input)
{
    size_t position = 0;

    memcpy(&this->command_code, input.data(), sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(&this->ack_code, input.data() + position, sizeof(uint8_t));
    position += sizeof(uint8_t);
}

int UploadAck::getSize()
{
    int size = 0;

    size += sizeof(uint8_t);
    size += sizeof(uint8_t);

    return size;
}

void UploadAck::print() const
{
    cout << "---------- UPLOAD ACK ---------" << endl;
    cout << "Acknowledge Code: " << ack_code << endl;
    cout << "------------------------------" << endl;
}

// ---------------------------------- UPLOAD M2 -----------------------------------

UploadM2::UploadM2() {}

UploadM2::UploadM2(Buffer file_chunk)
{
    command_code = RequestCodes::UPLOAD_CHUNK;
    this->file_chunk = file_chunk;
}

Buffer UploadM2::serialize()
{
    size_t chunk_size = file_chunk.size();
    Buffer buff(UploadM2::getSize(chunk_size));

    size_t position = 0;

    memcpy(buff.data(), &command_code, sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(buff.data() + position, file_chunk.data(), chunk_size * sizeof(unsigned char));
    position += chunk_size * sizeof(unsigned char);

    return buff;
}

void UploadM2::deserialize(Buffer input)
{
    size_t chunk_size = input.size() - sizeof(uint8_t);
    this->file_chunk = Buffer(chunk_size);

    size_t position = 0;

    memcpy(&this->command_code, input.data(), sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(this->file_chunk.data(), input.data() + position, chunk_size * sizeof(unsigned char));
}

size_t UploadM2::getSize(size_t chunk_size)
{
    int size = 0;

    size += sizeof(uint8_t);
    size += chunk_size * sizeof(unsigned char);

    return size;
}

void UploadM2::print() const
{

    cout << "--------- UPLOAD M2 --------" << endl;
    cout << "File chunk: ";
    for (Buffer::const_iterator it = file_chunk.begin(); it < file_chunk.end(); ++it)
        printf("%c", *it);
    cout << "\nCHUNK SIZE: " << file_chunk.size() << endl;
    cout << "------------------------------" << endl;
}
