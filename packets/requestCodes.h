#ifndef _REQUEST_CODES_H
#define _REQUEST_CODES_H

#include <cstddef>

constexpr size_t KB = 1024;

namespace RequestCodes
{
    const size_t UPLOAD_REQ = 1;
    const size_t DOWNLOAD_REQ = 2;
}

namespace maxSizes
{

    const size_t filename = 255; // linux file name length limit
    const size_t username = 30;
    const size_t fileChunk = 128 * KB;

}

#endif // _REQUEST_CODES_H
