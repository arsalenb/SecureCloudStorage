#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>
#include <constants.h>
#include <vector>

using namespace std;

typedef vector<unsigned char> Buffer;

// ----------------------------------- LIST REQUEST ------------------------------------

class ListM1
{
private:
    uint8_t command_code;

public:
    ListM1();
    Buffer serialize() const;
    void deserialize(Buffer buffer);
    static int getSize();
};

// ----------------------------------- LIST ACKNOWLEDGEMENT ------------------------------------

class ListM2
{
private:
    uint8_t command_code;
    uint8_t ack_code;
    uint32_t file_list_size;

public:
    ListM2();
    ListM2(uint8_t ack_code, uint32_t file_list_size);
    Buffer serialize() const;
    void deserialize(Buffer buffer);
    static int getSize();
    uint8_t getAckCode() { return ack_code; };
    uint32_t getFile_List_Size() { return file_list_size; };
    void print() const;
};

// ----------------------------------- LIST M3 ------------------------------------

class ListM3
{
private:
    uint8_t command_code;
    uint32_t file_list_size;
    char *file_list_data;

public:
    ListM3();
    ListM3(uint32_t file_list_size);
    Buffer serialize();
    void deserialize(Buffer buffer);
    int getSize();
    // Setter for file_list_data
    void setFileListData(const char *data);
    // Getter for file_list_data
    const char *getFileListData() const;
};
