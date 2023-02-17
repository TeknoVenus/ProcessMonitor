//
// Created by Stephen F on 15/02/23.
//

#include "CsvWriter.h"
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include "Log.h"

CsvWriter::CsvWriter() : mCsv()
{
    // Write header
    mCsv << "pid,parent_pid,start_time,duration_ms,exit_code,name,parent_name\n";
}

void CsvWriter::AddEntry(const processInfo &info)
{
    mCsv << info.pid << ',' << info.parentPid << ',' << getTimestamp(info.execSystemTime) << ','
         << info.duration.count() << ',' << info.exitCode << ',' << info.name << ',' << info.parentName << "\n";
}

std::string CsvWriter::getTimestamp(const std::chrono::time_point<std::chrono::system_clock> timestamp)
{
    std::time_t time = std::chrono::system_clock::to_time_t(timestamp);
    auto localTime = std::localtime(&time);

    auto epochTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(timestamp.time_since_epoch()).count();

    std::stringstream output;
    output << std::setfill('0') << std::put_time(localTime, "%FT%H:%M:") << std::setw(2) << (epochTimestamp / 1000) % 60
           << '.' << std::setw(3) << epochTimestamp % 1000;

    return output.str();
}

void CsvWriter::Print(const std::filesystem::path& outputFile)
{
    if (std::filesystem::exists(outputFile))
    {
        std::filesystem::remove(outputFile);
    }

    Log("Writing CSV to %s", outputFile.string().c_str());

    std::ofstream output(outputFile);
    if (output.is_open())
    {
        output << mCsv.str() << "\n";
    }
}
