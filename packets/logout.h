#ifndef _LOGOUT_H
#define _LOGOUT_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>
#include <constants.h>
#include <vector>

using namespace std;

typedef vector<unsigned char> Buffer;

// ----------------------------------- LOGOUT M1 ------------------------------------

class LogoutM1
{
private:
    uint8_t command_code;

public:
    LogoutM1();
    Buffer serialize() const;
    void deserialize(Buffer buffer);
    static int getSize();
};

// ----------------------------------- LOGOUT ACK ------------------------------------

class LogoutAck
{
private:
    uint8_t command_code;
    uint8_t ack_code;

public:
    LogoutAck();
    LogoutAck(uint8_t ack_code);
    Buffer serialize() const;
    void deserialize(Buffer buffer);
    static int getSize();
    uint8_t getAckCode() { return ack_code; };
    void print() const;
};

#endif // _LOGOUT_H
