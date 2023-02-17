//
// Created by Stephen F on 15/02/23.
//

#pragma once

#include <string>
#include <sstream>
#include "Process.h"
#include <filesystem>

class CsvWriter
{
public:
    CsvWriter();

    void AddEntry(const processInfo& info);
    void Print(const std::filesystem::path& outputFile);

private:
    static std::string getTimestamp(std::chrono::time_point<std::chrono::system_clock> timestamp);

private:
    std::stringstream mCsv;
};
