#ifndef _WORKER_H
#define _WORKER_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>
#include <vector>

using namespace std;

typedef std::vector<unsigned char> Buffer;
class Worker
{
private:
    std::string username;
    int communcation_socket;
    Buffer session_key;
    int s_counter = 0;
    int r_counter = 0;

public:
    Worker(int communcation_socket);

    // Private session key exchange
    int login();

    // --------- Application Routines ---------
    int upload_file(Buffer payload);
    int download_file(Buffer payload);
    int list_files(Buffer payload);
    int rename_file(Buffer payload);
    int delete_file(Buffer payload);
    int logout(Buffer payload);
    // ----------------------------------------

    // Start server worker
    int start();

    ~Worker();
};

#endif