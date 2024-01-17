#ifndef _WRAPPER_H
#define _WRAPPER_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>
#include <vector>

using namespace std;

typedef vector<unsigned char> Buffer;

class Wrapper
{
private:
    int counter;
    Buffer pt;
    Buffer ct;
    Buffer session_key;
    Buffer createAAD(int counter, Buffer iv);

public:
    Wrapper();
    Wrapper(Buffer session_key);
    Wrapper(Buffer session_key, int counter, Buffer payload);
    Buffer serialize();
    int deserialize(Buffer wrapper);
    static size_t getSize(size_t pt_size);
    Buffer getPayload() { return pt; }
    int getCounter() { return counter; }
    void print() const;
};

#endif // _WRAPPER_H
