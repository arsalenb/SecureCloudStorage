#include "./file.h"
#include <regex>
#include <filesystem>
#include <fstream>
#include <iostream>

File::File() {}

void File::read(const std::string &filePath)
{
    // Validate file path
    if (!File::exists(filePath))
    {
        throw std::invalid_argument("File does not exist.");
    }

    // Extract file name and size
    file_name = fs::path(filePath).filename().string();
    file_size = fs::file_size(filePath);

    // Sanitize file name using regex e.g.: '!invalid.txt' is not accepted
    if (!isValidFileName(file_name))
    {
        throw std::invalid_argument("Invalid file name.");
    }

    input_fs.open(file_name, std::ios::binary);

    if (!input_fs)
    {
        throw std::runtime_error("Unable to open file for reading.");
    }
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
    if (!input_fs)
    {
        throw std::runtime_error("File stream not open.");
    }

    // Read the specified chunk size from the file
    std::vector<unsigned char> buffer(chunkSize);
    input_fs.read(reinterpret_cast<char *>(buffer.data()), chunkSize);

    if (!input_fs)
    {
        throw std::runtime_error("Unable to read from file.");
    }

    return buffer;
}

bool File::exists(std::string filePath)
{

    if (!fs::exists(filePath))
    {
        return false;
    }

    if (!fs::is_regular_file(filePath))
    {
        return false;
    }

    return true;
}

void File::create(const std::string &filePath)
{
    // Validate file path
    if (File::exists(filePath))
    {
        throw std::invalid_argument("File already exists.");
    }

    // Sanitize file name using regex e.g.: '!invalid.txt' is not accepted
    if (!isValidFileName(fs::path(filePath).filename().string()))
    {
        throw std::invalid_argument("Invalid file name.");
    }

    // Create the file with the provided path
    output_fs.open(filePath, std::ios::binary | std::ios::out);

    if (!output_fs)
    {
        throw std::runtime_error("Unable to create file.");
    }

    // Update the file_name member variable
    file_name = fs::path(filePath).filename().string();
}

void File::writeChunk(const std::vector<unsigned char> &chunk)
{
    if (!output_fs)
    {
        throw std::runtime_error("File stream not open.");
    }

    // Write the chunk to the file
    output_fs.write(reinterpret_cast<const char *>(chunk.data()), chunk.size());

    if (!output_fs)
    {
        throw std::runtime_error("Unable to write to file.");
    }
}

File::~File()
{
    if (input_fs.is_open())
        input_fs.close();

    if (output_fs.is_open())
        output_fs.close();
}