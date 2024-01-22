#ifndef _CONSTANTS_H
#define _CONSTANTS_H
#include <array>
#include <cstddef>
#include <limits>
#include <openssl/evp.h>

const std::array<std::string, 3> username_list = {"user1", "user2", "user3"};

namespace ServerDetails
{
    const int PORT = 8080;
    const std::string SERVER_IP = "127.0.0.1";
}

namespace RequestCodes
{
    const size_t ACK_MSG = 0;
    const size_t UPLOAD_REQ = 1;
    const size_t UPLOAD_CHUNK = 2;
    const size_t DOWNLOAD_REQ = 3;
    const size_t DOWNLOAD_CHUNK = 4;
    const size_t LIST_REQ = 5;
    const size_t RENAME_REQ = 6;
    const size_t DELETE_REQ = 7;
    const size_t LOGOUT_REQ = 8;
}

namespace MAX
{

    const size_t file_name = 255; // linux file name length limit
    const size_t username_length = 50;
    const size_t passowrd_length = 50;
    const size_t max_file_chunk = 15;                                 // 1KB
    const size_t max_file_size = 4ULL * 1024 * 1024 * 1024;           // 4GB in bytes
    const size_t path = 4096;                                         // linux os imposed max absolute path length
    const size_t ack_msg = 50 + 1;                                    // extra char for str terminator
    const size_t counter_max_value = std::numeric_limits<int>::max(); // number of requests before shutting down the session
    const size_t initial_request_length = 520;                        // size of the initial request size to be expected

}

#endif // _REQUEST_CODES_H
