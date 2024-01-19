#include "delete.h"
#include <vector>
#include <arpa/inet.h>

// ----------------------------------- Delete M1 ------------------------------------

DeleteM1::DeleteM1() {}
DeleteM1::DeleteM1(string file_name)
{

    this->command_code = RequestCodes::DELETE_REQ;
    strncpy(this->file_name, file_name.c_str(), MAX::file_name + 1);
}

Buffer DeleteM1::serialize() const
{
    Buffer buff(MAX::initial_request_length);

    size_t position = 0;

    // insert the command code unint8_t (one byte) interepreted as unsigned char
    memcpy(buff.data(), &command_code, sizeof(uint8_t));

    position += sizeof(uint8_t);

    // insert the file_name string which has a size of max of file name (255) +1
    unsigned char const *file_name_pointer = reinterpret_cast<unsigned char const *>(&file_name);
    memcpy(buff.data() + position, file_name_pointer, ((MAX::file_name + 1) * sizeof(char)));
    position += (MAX::file_name + 1) * sizeof(char);

    return buff;
}

void DeleteM1::deserialize(Buffer input)
{
    size_t position = 0;

    memcpy(&this->command_code, input.data(), sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(&this->file_name, input.data() + position, (MAX::file_name + 1) * sizeof(char));
}

int DeleteM1::getSize()
{

    int size = 0;

    size += sizeof(uint8_t);
    size += (MAX::file_name + 1) * sizeof(char); // max file_name_length

    return size;
}

void DeleteM1::print() const
{
    cout << "---------- Delete M1 ---------" << endl;
    cout << "FILE NAME: " << file_name << endl;
}

// ----------------------------------- Delete ACKNOWLEDGEMENT ------------------------------------
DeleteAck::DeleteAck() {}

DeleteAck::DeleteAck(uint8_t ack_code)
{
    this->command_code = RequestCodes::DELETE_REQ;
    this->ack_code = ack_code;
}

Buffer DeleteAck::serialize() const
{
    Buffer buff(DeleteAck::getSize());
    size_t position = 0;

    memcpy(buff.data(), &command_code, sizeof(uint8_t));
    position += sizeof(uint8_t);

    // Insert ack_code into the buffer
    memcpy(buff.data() + position, &ack_code, sizeof(uint8_t));

    return buff;
}

void DeleteAck::deserialize(Buffer input)
{

    size_t position = 0;

    // Extract command_code from the buffer
    memcpy(&this->command_code, input.data(), sizeof(uint8_t));
    position += sizeof(uint8_t);

    // Extract ack_code from the buffer
    memcpy(&this->ack_code, input.data() + position, sizeof(uint8_t));
}

int DeleteAck::getSize()
{
    int size = 0;

    size += sizeof(uint8_t);
    size += sizeof(uint8_t);

    return size;
}

void DeleteAck::print() const
{
    cout << "---------- Delete ACKNOWLEDGEMENT ---------" << endl;
    cout << "Acknowledge message: " << ack_code << endl;
    cout << "--------------------------------------------" << endl;
}
