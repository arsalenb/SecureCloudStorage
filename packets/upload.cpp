#include "./Upload.h"
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
    Buffer buff;
    uint32_t no_file_size; // network order file size

    // insert the command code unint8_t (one byte) interepreted as unsigned char
    buff.insert(buff.begin(), command_code);

    // insert the file string which has a size of max of file name (50) +1
    unsigned char const *file_name_pointer = reinterpret_cast<unsigned char const *>(&file_name);
    buff.insert(buff.end(), file_name_pointer, file_name_pointer + ((MAX::file_name + 1) * sizeof(char)));

    // change host to network byte order of file_size
    no_file_size = htonl(file_size);

    // set the file_size_begin pointer on the uint32_t value
    unsigned char const *file_size_begin = reinterpret_cast<unsigned char const *>(&no_file_size);

    // insert file size into the vector which is on uint32_t
    buff.insert(buff.end(), file_size_begin, file_size_begin + sizeof(uint32_t));

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
    size += sizeof(uint32_t);
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
UploadAck::UploadAck(string ack_msg)
{

    this->commandCode = RequestCodes::UPLOAD_REQ;
    strncpy(this->ack_msg, ack_msg.c_str(), MAX::ack_msg + 1);
}

Buffer UploadAck::serialize() const
{
    Buffer buff;

    buff.insert(buff.begin(), commandCode);

    unsigned char const *ack_msg_pointer = reinterpret_cast<unsigned char const *>(&ack_msg);
    buff.insert(buff.end(), ack_msg_pointer, ack_msg_pointer + ((MAX::ack_msg + 1) * sizeof(char)));

    return buff;
}

void UploadAck::deserialize(Buffer input)
{
    UploadAck UploadM2;
    size_t position = 0;

    memcpy(&this->commandCode, input.data(), sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(&this->ack_msg, input.data() + position, (MAX::ack_msg + 1) * sizeof(char));
}

int UploadAck::getSize()
{

    int size = 0;
    size += (MAX::ack_msg + 1) * sizeof(char);

    return size;
}

void UploadAck::print() const
{
    cout << "---------- UPLOAD M2 ---------" << endl;
    cout << "Acknowledge message: " << ack_msg << endl;
    cout << "------------------------------" << endl;
}

// ---------------------------------- UPLOAD M3 -----------------------------------

UploadM3::UploadM3(Buffer file_chunk)
{
    command_code = RequestCodes::UPLOAD_CHUNK;
    this->file_chunk = file_chunk;
}

Buffer UploadM3::serialize() const
{
    Buffer buff;

    buff.insert(buff.begin(), command_code);
    buff.insert(buff.end(), file_chunk.data(), file_chunk.data() + file_chunk.size());

    return buff;
}

void UploadM3::deserialize(Buffer input)
{

    size_t position = 0;

    memcpy(&this->command_code, input.data(), sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(&this->file_chunk, input.data() + position, input.size() - sizeof(uint8_t));
}

int UploadM3::getSize()
{
    int size = 0;

    size += sizeof(uint8_t);
    size += sizeof(uint32_t);
    size += file_chunk.size();

    return size;
}

void UploadM3::print() const
{

    cout << "--------- UPLOAD M3 --------" << endl;
    cout << "File chunk: ";
    for (Buffer::const_iterator it = file_chunk.begin(); it < file_chunk.end(); ++it)
        printf("%02X", *it);
    cout << "\n CHUNK SIZE: " << file_chunk.size() << endl;
    cout << "------------------------------" << endl;
}
