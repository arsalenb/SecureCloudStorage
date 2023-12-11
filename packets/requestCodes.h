#ifndef _REQUEST_CODES_H
#define _REQUEST_CODES_H

#include <cstddef>

constexpr size_t KB = 1024;

namespace RequestCodes
{
    const size_t ACK_MSG = 0;
    const size_t UPLOAD_REQ = 1;
    const size_t UPLOAD_CHUNK = 2;
    const size_t DOWNLOAD_REQ = 3;
}

namespace maxSizes
{

    const size_t filename = 255; // linux file name length limit
    const size_t USERNAME_MAX = 30;
    const size_t FILE_CHUNK_MAX = 128 * KB;
    const size_t path = 4096;      // linux os imposed max absolute path length
    const size_t ack_msg = 50 + 1; // extra char for str terminator

}

#endif // _REQUEST_CODES_H
