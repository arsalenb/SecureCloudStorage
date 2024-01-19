#ifndef FILE_H
#define FILE_H

#include <iostream>
#include <filesystem>
#include <string>
#include <stdexcept>
#include <fstream>

namespace fs = std::filesystem;

class File
{
private:
    std::string file_name;
    uintmax_t file_size;
    std::ifstream input_fs;
    std::ofstream output_fs;

public:
    File();
    void read(const std::string &filePath);
    void writeChunk(const std::vector<unsigned char> &chunk);
    void create(const std::string &filePath);
    bool isValidFileName(const std::string &name);
    void displayFileInfo() const;
    std::vector<unsigned char> readChunk(std::size_t chunkSize);
    uintmax_t getFileSize() { return file_size; }
    std::string get_file_name() { return file_name; };
    static bool exists(std::string filePath);
    std::string getFileNames(const std::string &folderPath);
    int changeFileName(const std::string &filePath, const std::string &newFilePath);
    int deleteFile(const std::string &filePath);
    ~File();
};

#endif // FILE_H
