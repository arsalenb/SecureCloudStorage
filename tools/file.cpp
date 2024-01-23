#include "./file.h"
#include <regex>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <numeric>
#include "constants.h"

using namespace std;

File::File()
{
}

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
    if (!isValidFileName(file_name) || file_name.size() > MAX::file_name)
    {
        throw std::invalid_argument("Invalid file name.");
    }

    input_fs.open(filePath, std::ios::binary);

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
    // Update the file_name member variable
    file_name = fs::path(filePath).filename().string();

    // Sanitize file name using regex e.g.: '!invalid.txt' is not accepted
    if (!isValidFileName(file_name) || file_name.size() > MAX::file_name)
    {
        throw std::invalid_argument("Invalid file name.");
    }

    // Create the file with the provided path
    output_fs.open(filePath, std::ios::binary | std::ios::out);

    if (!output_fs)
    {
        throw std::runtime_error("Unable to create file.");
    }
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

std::string File::getFileNames(const std::string &folderPath)
{
    std::vector<std::string> fileNames;

    try
    {
        for (const auto &entry : std::filesystem::directory_iterator(folderPath))
        {
            if (entry.is_regular_file())
            {
                fileNames.push_back(entry.path().filename().string());
            }
        }
    }
    catch (const std::filesystem::filesystem_error &ex)
    {
        std::cerr << "Error accessing folder: " << ex.what() << std::endl;
        return ""; // Return an empty string to indicate an error
    }

    // Join the file names using commas
    return std::accumulate(fileNames.begin(), fileNames.end(), std::string(),
                           [](const std::string &a, const std::string &b) -> std::string
                           {
                               return a + (a.length() > 0 ? "," : "") + b;
                           });
}

int File::changeFileName(const std::string &filePath, const std::string &newFilePath)
{

    // Rename the file
    return rename(filePath.c_str(), newFilePath.c_str());
}

int File::deleteFile(const std::string &filePath)
{

    // Rename the file
    return remove(filePath.c_str());
}