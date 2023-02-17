//
// Created by Stephen F on 15/02/23.
//

#pragma once

#include <string>
#include <chrono>

struct processInfo
{
    pid_t pid;
    pid_t parentPid;

    std::chrono::time_point<std::chrono::system_clock> endTime;
    std::chrono::time_point<std::chrono::system_clock> startTime;

    uint32_t exitCode;

    std::string name;
    std::string commandLine;

    std::string parentName;
    std::string parentCommandLine;
};
