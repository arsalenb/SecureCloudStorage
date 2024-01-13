#ifndef _UPLOAD_H
#define _UPLOAD_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>
#include <constants.h>
#include <vector>

using namespace std;

typedef vector<unsigned char> Buffer;

// ----------------------------------- UPLOAD M1 ------------------------------------

class UploadM1
{
private:
    uint8_t command_code;
    uint32_t file_size; // 32 bit unsigned that can represent up to 4GB file sizes

public:
    char file_name[MAX::file_name + 1]; // cstyle string to hold file name plus the '\n'

    UploadM1();
    UploadM1(string file_name, uint32_t file_size);
    Buffer serialize() const;
    void deserialize(Buffer buffer);
    static int getSize();
    void print() const;
};

// ----------------------------------- UPLOAD ACK ------------------------------------

class UploadAck
{
private:
    uint8_t command_code;
    uint8_t ack_code;

public:
    UploadAck();
    UploadAck(uint8_t ack_code);
    Buffer serialize() const;
    void deserialize(Buffer buffer);
    static int getSize();
    uint8_t getAckCode() { return ack_code; };
    void print() const;
};

// ---------------------------------- UPLOAD M3 -----------------------------------

class UploadM3
{
private:
    uint8_t command_code;
    Buffer file_chunk;

public:
    UploadM3(Buffer file_chunk);
    Buffer serialize() const;
    void deserialize(Buffer file_chunk);
    static size_t getSize(size_t chunk_size);
    void print() const;
};

// ----------------------------------------------------------------------------------

#endif // _UPLOAD_H
