#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>
#include <constants.h>
#include <vector>

using namespace std;

typedef vector<unsigned char> Buffer;

// ----------------------------------- Delete M1 ------------------------------------

class DeleteM1
{
private:
    uint8_t command_code;

public:
    // cstyle string to hold file name plus the '\n'
    char file_name[MAX::file_name + 1];
    DeleteM1();
    DeleteM1(string file_name);
    Buffer serialize() const;
    void deserialize(Buffer buffer);
    static int getSize();
    void print() const;
};
// ----------------------------------- Delete ACKNOWLEDGEMENT ------------------------------------

class DeleteAck
{
private:
    uint8_t command_code;
    uint8_t ack_code;

public:
    DeleteAck();
    DeleteAck(uint8_t ack_code);
    Buffer serialize() const;
    void deserialize(Buffer buffer);
    static int getSize();
    uint8_t getAckCode() { return ack_code; };
    void print() const;
};