// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Stephen Foulds

#pragma once

#include "Process.h"
#include <algorithm>
#include <condition_variable>
#include <json.hpp>
#include <list>
#include <memory>
#include <optional>
#include <regex>
#include <string>
#include <thread>
#include <vector>

class ProcessMonitor
{
public:
    ProcessMonitor();
    ~ProcessMonitor();

    ProcessMonitor(const ProcessMonitor &) = delete;
    ProcessMonitor &operator=(const ProcessMonitor &) = delete;

    bool Start();
    bool Stop();

    std::string GetJson();

private:
    bool setListenMode(bool enable) const;

    void receiveMessages();
    static void getProcessCommandLine(pid_t pid, std::string &commandLine);
    [[nodiscard]] static pid_t getParentPid(pid_t pid);
    void setSocketFilter() const;

    std::string getSystemdService(pid_t pid);

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
};
