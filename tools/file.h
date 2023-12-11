#ifndef FILE_H
#define FILE_H

#include <iostream>
#include <filesystem>
#include <string>
#include <stdexcept>

namespace fs = std::filesystem;

class File
{
private:
    std::string file_name;
    uintmax_t file_size;
    std::ifstream file_stream;

public:
    File(const std::string &filePath);
    bool File::isValidFileName(const std::string &name);
    void displayFileInfo() const;
    std::vector<unsigned char> readChunk(std::size_t chunkSize);
    ~File();
};

#endif // FILE_H
