#ifndef _CONSTANTS_H
#define _CONSTANTS_H

#include <cstddef>
#include <limits>
#include <openssl/evp.h>

namespace RequestCodes
{
    const size_t ACK_MSG = 0;
    const size_t UPLOAD_REQ = 1;
    const size_t UPLOAD_CHUNK = 2;
    const size_t DOWNLOAD_REQ = 3;
    const size_t DOWNLOAD_CHUNK = 4;
}

namespace MAX
{

    const size_t file_name = 255; // linux file name length limit
    const size_t username_length = 30;
    const size_t max_file_chunk = 128 * 1024;                         // 128KB
    const size_t max_file_size = 4ULL * 1024 * 1024 * 1024;           // 4GB in bytes
    const size_t path = 4096;                                         // linux os imposed max absolute path length
    const size_t ack_msg = 50 + 1;                                    // extra char for str terminator
    const size_t counter_max_value = std::numeric_limits<int>::max(); // number of requests before shutting down the session
    const size_t initial_request_length = 520;                        // size of the initial request size to be expected
}

#endif // _REQUEST_CODES_H
