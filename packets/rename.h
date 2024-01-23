#ifndef _RENAME_H
#define _RENAME_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>
#include <constants.h>
#include <vector>

using namespace std;

typedef vector<unsigned char> Buffer;

// ----------------------------------- Rename M1 ------------------------------------

class RenameM1
{
private:
    uint8_t command_code;

public:
    // cstyle string to hold file name plus the '\n'
    char file_name[MAX::file_name + 1];
    char new_file_name[MAX::file_name + 1];
    RenameM1();
    RenameM1(string file_name, string new_file_name);
    Buffer serialize() const;
    void deserialize(Buffer buffer);
    static int getSize();
    void print() const;
};
// ----------------------------------- RENAME ACKNOWLEDGEMENT ------------------------------------

class RenameAck
{
private:
    uint8_t command_code;
    uint8_t ack_code;

public:
    RenameAck();
    RenameAck(uint8_t ack_code);
    Buffer serialize() const;
    void deserialize(Buffer buffer);
    static int getSize();
    uint8_t getAckCode() { return ack_code; };
    void print() const;
};

#endif
