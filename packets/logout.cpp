#include "./logout.h"
#include <vector>
#include <arpa/inet.h>

// ----------------------------------- LOGOUT M1 ------------------------------------

LogoutM1::LogoutM1()
{

    this->command_code = RequestCodes::LOGOUT_REQ;
}

Buffer LogoutM1::serialize() const
{
    Buffer buff(MAX::initial_request_length);

    size_t position = 0;

    // insert the command code unint8_t (one byte) interepreted as unsigned char
    memcpy(buff.data(), &command_code, sizeof(uint8_t));

    position += sizeof(uint8_t);

    return buff;
}

void LogoutM1::deserialize(Buffer input)
{
    size_t position = 0;

    memcpy(&this->command_code, input.data(), sizeof(uint8_t));
    position += sizeof(uint8_t);
}

int LogoutM1::getSize()
{
    return sizeof(uint8_t);
}

// ----------------------------------- LOGOUT ACK ------------------------------------

LogoutAck::LogoutAck() {}
LogoutAck::LogoutAck(uint8_t ack_code)
{
    this->command_code = RequestCodes::LOGOUT_REQ;
    this->ack_code = ack_code;
}

Buffer LogoutAck::serialize() const
{
    Buffer buff(LogoutAck::getSize());
    size_t position = 0;

    memcpy(buff.data(), &command_code, sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(buff.data() + position, &ack_code, sizeof(uint8_t));
    position += sizeof(uint8_t);

    return buff;
}

void LogoutAck::deserialize(Buffer input)
{
    size_t position = 0;

    memcpy(&this->command_code, input.data(), sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(&this->ack_code, input.data() + position, sizeof(uint8_t));
    position += sizeof(uint8_t);
}

int LogoutAck::getSize()
{
    int size = 0;

    size += sizeof(uint8_t);
    size += sizeof(uint8_t);

    return size;
}

void LogoutAck::print() const
{
    cout << "---------- LOGOUT ACK ---------" << endl;
    cout << "Acknowledge Code: " << ack_code << endl;
    cout << "------------------------------" << endl;
}