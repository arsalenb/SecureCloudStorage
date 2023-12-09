#include "Upload.h"
#include "requestCodes.h"

// ----------------------------------- UPLOAD M1 ------------------------------------

UploadM1::UploadM1(uint32_t counter, string file_name, size_t file_size)
{

    this->commandCode = RequestCodes::UPLOAD_REQ;
    this->counter = counter;
    strncpy(this->file_name, file_name.c_str(), FILE_NAME_SIZE);
    this->file_size = (file_size < 4UL * 1024 * 1024 * 1024) ? (uint32_t)file_size : 0;
}

uint8_t *UploadM1::serialize() const
{
    uint8_t *buffer = new uint8_t[COMMAND_FIELD_PACKET_SIZE];

    size_t position = 0;
    memcpy(buffer, &commandCode, sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(buffer + position, &counter, sizeof(uint32_t));
    position += sizeof(uint32_t);

    memcpy(buffer + position, file_name, FILE_NAME_SIZE * sizeof(char));
    position += FILE_NAME_SIZE * sizeof(char);

    memcpy(buffer + position, &file_size, sizeof(uint32_t));
    position += sizeof(uint32_t);

    // add random bytes
    RAND_bytes(buffer + position, COMMAND_FIELD_PACKET_SIZE - position);

    return buffer;
}

UploadM1 UploadM1::deserialize(uint8_t *buffer)
{
    UploadM1 uploadM1;

    size_t position = 0;
    memcpy(&uploadM1.commandCode, buffer, sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(&uploadM1.counter, buffer + position, sizeof(uint32_t));
    position += sizeof(uint32_t);

    memcpy(uploadM1.file_name, buffer + position, FILE_NAME_SIZE * sizeof(char));
    position += FILE_NAME_SIZE * sizeof(char);

    memcpy(&uploadM1.file_size, buffer + position, sizeof(uint32_t));

    return uploadM1;
}

int UploadM1::getSize()
{

    int size = 0;

    size += sizeof(uint8_t);
    size += sizeof(uint32_t);
    size += FILE_NAME_SIZE * sizeof(char);
    size += sizeof(uint32_t);

    return size;
}

void UploadM1::print() const
{
    cout << "---------- UPLOAD M1 ---------" << endl;
    cout << "COUNTER: " << counter << endl;
    cout << "FILE NAME: " << file_name << endl;
    cout << "FILE SIZE: " << file_size << endl;
    cout << "------------------------------" << endl;
}

// ---------------------------------- UPLOAD M3+i -----------------------------------

UploadMi::UploadMi(uint32_t counter, uint8_t *chunk, int chunk_size)
{
    this->command_code = FILE_CHUNK;
    this->counter = counter;
    this->chunk = new uint8_t[chunk_size];
    memcpy(this->chunk, chunk, chunk_size);
    this->chunk_size = chunk_size;
}

UploadMi::~UploadMi()
{
    delete[] chunk;
}

uint8_t *UploadMi::serialize() const
{
    uint8_t *buffer = new uint8_t[UploadMi::getSize(chunk_size)];

    size_t position = 0;
    memcpy(buffer, &command_code, sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(buffer + position, &counter, sizeof(uint32_t));
    position += sizeof(uint32_t);

    memcpy(buffer + position, chunk, chunk_size * sizeof(uint8_t));

    return buffer;
}

UploadMi UploadMi::deserialize(uint8_t *buffer, int chunk_size)
{
    UploadMi uploadMi;

    size_t position = 0;
    memcpy(&uploadMi.command_code, buffer, sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(&uploadMi.counter, buffer + position, sizeof(uint32_t));
    position += sizeof(uint32_t);

    uploadMi.chunk = new uint8_t[chunk_size];
    memcpy(uploadMi.chunk, buffer + position, chunk_size * sizeof(uint8_t));
    uploadMi.chunk_size = chunk_size;

    return uploadMi;
}

int UploadMi::getSize(int chunk_size)
{
    int size = 0;

    size += sizeof(uint8_t);
    size += sizeof(uint32_t);
    size += chunk_size * sizeof(uint8_t);

    return size;
}

void UploadMi::print() const
{
    cout << "--------- UPLOAD M3+i --------" << endl;
    cout << "COUNTER: " << counter << endl;
    cout << "CHUNK (first 10byte): ";
    int byte_to_print = chunk_size < 10 ? chunk_size : 10;
    for (int i = 0; i < byte_to_print; ++i)
        cout << hex << (int)chunk[i];
    cout << dec << endl;
    cout << "CHUNK SIZE: " << chunk_size << endl;
    cout << "------------------------------" << endl;
}
