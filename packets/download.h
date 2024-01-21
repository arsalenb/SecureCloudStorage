#ifndef _DOWNLOAD_H
#define _DOWNLOAD_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>
#include <constants.h>
#include <vector>

using namespace std;

typedef vector<unsigned char> Buffer;

// ----------------------------------- DOWNLOAD REQUEST ------------------------------------

class DownloadM1
{
private:
    uint8_t command_code;

public:
    char file_name[MAX::file_name + 1];

    DownloadM1();
    DownloadM1(string file_name);
    Buffer serialize() const;
    void deserialize(Buffer buffer);
    static int getSize();
    void print() const;
};

// ----------------------------------- DOWNLOAD ACKNOWLEDGEMENT ------------------------------------

class DownloadAck
{
private:
    uint8_t command_code;
    uint8_t ack_code;
    uint32_t file_size;

public:
    DownloadAck();
    DownloadAck(uint8_t ack_code);
    DownloadAck(uint8_t ack_code, uint32_t file_size);
    Buffer serialize() const;
    void deserialize(Buffer buffer);
    static int getSize();
    uint8_t getAckCode() { return ack_code; };
    uint32_t getFileSize() { return file_size; };
    void print() const;
};

// ---------------------------------- DOWNLOAD M2 -----------------------------------

class DownloadM2
{
private:
    uint8_t command_code;
    Buffer file_chunk;

public:
    DownloadM2();
    DownloadM2(Buffer file_chunk);
    Buffer serialize() const;
    void deserialize(Buffer file_chunk);
    static size_t getSize(size_t chunk_size);
    Buffer getFileChunk() { return file_chunk; }
    void print() const;
};

// ----------------------------------------------------------------------------------

#endif // _DOWNLOAD_H
