#include "rename.h"
#include <vector>
#include <arpa/inet.h>

// ----------------------------------- Rename M1 ------------------------------------

RenameM1::RenameM1() {}
RenameM1::RenameM1(string file_name, string new_file_name)
{

    this->command_code = RequestCodes::RENAME_REQ;
    strncpy(this->file_name, file_name.c_str(), MAX::file_name + 1);
    strncpy(this->new_file_name, new_file_name.c_str(), MAX::file_name + 1);
}

Buffer RenameM1::serialize() const
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

    // insert the new_file_name string which has a size of max of file name (255) +1
    unsigned char const *new_file_name_pointer = reinterpret_cast<unsigned char const *>(&new_file_name);
    memcpy(buff.data() + position, new_file_name_pointer, ((MAX::file_name + 1) * sizeof(char)));

    return buff;
}

void RenameM1::deserialize(Buffer input)
{
    size_t position = 0;

    memcpy(&this->command_code, input.data(), sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(&this->file_name, input.data() + position, (MAX::file_name + 1) * sizeof(char));
    position += (MAX::file_name + 1) * sizeof(char);

    memcpy(&this->new_file_name, input.data() + position, (MAX::file_name + 1) * sizeof(char));
}

int RenameM1::getSize()
{

    int size = 0;

    size += sizeof(uint8_t);
    size += (MAX::file_name + 1) * sizeof(char); // max file_name_length
    size += (MAX::file_name + 1) * sizeof(char); // max new_file_name

    return size;
}

void RenameM1::print() const
{
    cout << "---------- RENAME M1 ---------" << endl;
    cout << "FILE NAME: " << file_name << endl;
    cout << "NEW FILE NAME: " << new_file_name << endl;
    cout << "------------------------------" << endl;
}

// ----------------------------------- RENAME ACKNOWLEDGEMENT ------------------------------------
RenameAck::RenameAck() {}

RenameAck::RenameAck(uint8_t ack_code)
{
    this->command_code = RequestCodes::RENAME_REQ;
    this->ack_code = ack_code;
}

Buffer RenameAck::serialize() const
{
    Buffer buff(RenameAck::getSize());
    size_t position = 0;

    memcpy(buff.data(), &command_code, sizeof(uint8_t));
    position += sizeof(uint8_t);

    // Insert ack_code into the buffer
    memcpy(buff.data() + position, &ack_code, sizeof(uint8_t));

    return buff;
}

void RenameAck::deserialize(Buffer input)
{

    size_t position = 0;

    // Extract command_code from the buffer
    memcpy(&this->command_code, input.data(), sizeof(uint8_t));
    position += sizeof(uint8_t);

    // Extract ack_code from the buffer
    memcpy(&this->ack_code, input.data() + position, sizeof(uint8_t));
}

int RenameAck::getSize()
{
    int size = 0;

    size += sizeof(uint8_t);
    size += sizeof(uint8_t);

    return size;
}

void RenameAck::print() const
{
    cout << "---------- RENAME ACKNOWLEDGEMENT ---------" << endl;
    cout << "Acknowledge message: " << ack_code << endl;
    cout << "--------------------------------------------" << endl;
}
