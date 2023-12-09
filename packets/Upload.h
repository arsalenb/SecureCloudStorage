#ifndef _UPLOAD_H
#define _UPLOAD_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

using namespace std;

// ----------------------------------- UPLOAD M1 ------------------------------------

class UploadM1
{
private:
    uint8_t commandCode;
    char file_name[maxSizes::filename];
    uint32_t file_size; // 32 bit unsigned that can represent up to 4GB file sizes

public:
    UploadM1(uint32_t counter, string file_name, size_t file_size);
    uint8_t *serialize() const;
    static UploadM1 deserialize(uint8_t *buffer);
    static int getSize();
    void print() const;
};

// ---------------------------------- UPLOAD M3+i -----------------------------------

class UploadMi
{
private:
    uint8_t command_code;
    uint32_t counter;
    uint8_t *chunk;
    int chunk_size; // used during serialize, not sent

public:
    UploadMi(uint32_t counter, uint8_t *chunk, int chunk_size);
    ~UploadMi();
    uint8_t *serialize() const;
    static UploadMi deserialize(uint8_t *buffer, int chunk_size);
    static int getSize(int chunk_size);
    void print() const;
};

// ----------------------------------------------------------------------------------

#endif // _UPLOAD_H
