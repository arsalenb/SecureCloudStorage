#include "./file.h"
#include <regex>
#include <filesystem>
#include <fstream>

File::File() {}

void File::read(const std::string &filePath)
{
    // Validate file path
    if (!fs::exists(filePath))
    {
        throw std::invalid_argument("File does not exist.");
    }

    if (!fs::is_regular_file(filePath))
    {
        throw std::invalid_argument("Not a regular file.");
    }

    // Extract file name and size
    file_name = fs::path(filePath).filename().string();
    file_size = fs::file_size(filePath);

    // Sanitize file name using regex e.g.: '!invalid.txt' is not accepted
    if (!isValidFileName(file_name))
    {
        throw std::invalid_argument("Invalid file name.");
    }

    file_stream.open(file_name, std::ios::binary);

    if (!file_stream)
    {
        throw std::runtime_error("Unable to open file for reading.");
    }
}

File::~File()
{
    file_stream.close();
}
bool File::isValidFileName(const std::string &name)
{
    // Use a regex pattern for valid file names
    static const std::regex validFileNamePattern(R"(^\w[\w.\-+_!#$%^&()]{0,19}$)");
    return std::regex_match(name, validFileNamePattern);
}

void File::displayFileInfo() const
{
    std::cout << "File Name: " << file_name << std::endl;
    std::cout << "File Size: " << file_size << " bytes" << std::endl;
}

std::vector<unsigned char> File::readChunk(std::size_t chunkSize)
{
    if (!file_stream)
    {
        throw std::runtime_error("File stream not open.");
    }

    // Read the specified chunk size from the file
    std::vector<unsigned char> buffer(chunkSize);
    file_stream.read(reinterpret_cast<char *>(buffer.data()), chunkSize);

    if (!file_stream)
    {
        throw std::runtime_error("Unable to read from file.");
    }

    return buffer;
}