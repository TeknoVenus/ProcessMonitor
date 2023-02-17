//
// Created by Stephen F on 09/02/23.
//

#pragma once

#include "Process.h"
#include <algorithm>
#include <condition_variable>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#include <list>
#include <json.hpp>

class ProcessMonitor
{
public:
    ProcessMonitor();
    ~ProcessMonitor();

    bool Start();
    bool Stop();

    std::string GetJson();

private:
    bool setListenMode(bool enable) const;

    void receiveMessages();
    void getProcessName(pid_t pid, std::string &name, std::string& commandLine) const;
    [[nodiscard]] pid_t getParentPid(pid_t pid) const;
    void setSocketFilter() const;

private:
    int mSocket;
    bool mListen;
    long mPageSize;

    bool mValid;

    nlohmann::json mProcessJson;

    std::thread mMessageReceiver;

    std::vector<processInfo> mRunningProcesses;
    std::vector<processInfo> mExitedProcesses;

    std::chrono::time_point<std::chrono::system_clock> mStart;
    std::chrono::time_point<std::chrono::system_clock> mEnd;

    // Prefixes from commands to strip
    std::list<std::string> mStripPrefixes;
};
