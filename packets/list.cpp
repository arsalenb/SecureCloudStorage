#include "list.h"
#include <vector>
#include <arpa/inet.h>
#include <iostream>

using namespace std;
// ----------------------------------- LIST M1 ------------------------------------

ListM1::ListM1()
{
    this->command_code = RequestCodes::LIST_REQ;
}

Buffer ListM1::serialize() const
{
    Buffer buff(MAX::initial_request_length);
    size_t position = 0;

    // insert the command code uint8_t (one byte) interpreted as unsigned char
    memcpy(buff.data(), &command_code, sizeof(uint8_t));
    return buff;
}

void ListM1::deserialize(Buffer input)
{
    size_t position = 0;

    memcpy(&this->command_code, input.data(), sizeof(uint8_t));
}

int ListM1::getSize()
{
    int size = 0;

    size += sizeof(uint8_t);
    size += (MAX::file_name + 1) * sizeof(char);

    return size;
}

// ----------------------------------- List ACKNOWLEDGEMENT ------------------------------------

ListM2::ListM2() {}

ListM2::ListM2(uint8_t ack_code, uint32_t file_list_size)
{
    this->command_code = RequestCodes::LIST_REQ;
    this->file_list_size = file_list_size;
    this->ack_code = ack_code;
}

Buffer ListM2::serialize() const
{
    Buffer buff(ListM2::getSize());
    size_t position = 0;

    memcpy(buff.data(), &command_code, sizeof(uint8_t));
    position += sizeof(uint8_t);

    // Convert file_list_size to network byte order
    uint32_t no_file_list_size = htonl(file_list_size);

    // Insert file_list_size into the buffer
    unsigned char const *file_size_begin = reinterpret_cast<unsigned char const *>(&no_file_list_size);
    memcpy(buff.data() + position, file_size_begin, sizeof(uint32_t));
    position += sizeof(uint32_t);

    // Insert ack_code into the buffer
    memcpy(buff.data() + position, &ack_code, sizeof(uint8_t));

    return buff;
}

void ListM2::deserialize(Buffer input)
{

    size_t position = 0;

    // Extract command_code from the buffer
    memcpy(&this->command_code, input.data(), sizeof(uint8_t));
    position += sizeof(uint8_t);

    // Extract file_size from the buffer
    uint32_t network_file_list_size = 0;
    memcpy(&network_file_list_size, input.data() + position, sizeof(uint32_t));
    file_list_size = ntohl(network_file_list_size);
    position += sizeof(uint32_t);

    // Extract ack_code from the buffer
    memcpy(&this->ack_code, input.data() + position, sizeof(uint8_t));
}

int ListM2::getSize()
{
    int size = 0;

    size += sizeof(uint8_t);
    size += sizeof(uint32_t); // file_list_size
    size += sizeof(uint8_t);

    return size;
}

void ListM2::print() const
{
    cout << "---------- List ACKNOWLEDGEMENT ---------" << endl;
    cout << "Acknowledge message: " << ack_code << endl;
    cout << "--------------------------------------------" << endl;
}

// ----------------------------------- List M3 ------------------------------------

ListM3::ListM3() {}

ListM3::ListM3(uint32_t file_list_size)
{
    this->command_code = RequestCodes::LIST_REQ;
    this->file_list_size = file_list_size;
}

Buffer ListM3::serialize()
{

    Buffer buff(getSize());
    size_t position = 0;

    memcpy(buff.data(), &command_code, sizeof(uint8_t));
    position += sizeof(uint8_t);

    // Insert file_list_data into the buffer
    memcpy(buff.data() + position, file_list_data, file_list_size);

    return buff;
}

void ListM3::deserialize(Buffer input)
{

    size_t position = 0;

    // Extract command_code from the buffer
    memcpy(&this->command_code, input.data(), sizeof(uint8_t));
    position += sizeof(uint8_t);

    file_list_data = new char[file_list_size + 1];
    // Extract file_list_data from the buffer
    memcpy(file_list_data, input.data() + position, file_list_size);
}

int ListM3::getSize()
{
    int size = 0;

    size += sizeof(uint8_t);
    size += file_list_size; // file_list_size

    return size;
}

void ListM3::setFileListData(const char *data)
{

    // Allocate new memory and copy the provided data
    file_list_data = new char[file_list_size + 1];
    std::memcpy(file_list_data, data, file_list_size);
}

const char *ListM3::getFileListData() const
{
    return file_list_data;
}
