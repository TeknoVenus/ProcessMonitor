// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Stephen Foulds

#include "ProcessMonitor.h"
#include "Log.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <fcntl.h>
#include <fstream>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <set>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#define OP_LDH (BPF_LD | BPF_H | BPF_ABS)
#define OP_LDB (BPF_LD | BPF_B | BPF_ABS)
#define OP_LDW (BPF_LD | BPF_W | BPF_ABS)
#define OP_JEQ (BPF_JMP | BPF_JEQ | BPF_K)
#define OP_RET (BPF_RET | BPF_K)
#define BPF_ALLOW 0xffffffff
#define BPF_DENY 0

/**
 * References:
 * * https://nick-black.com/dankwiki/index.php/The_Proc_Connector_and_Socket_Filters
 * * https://bewareofgeek.livejournal.com/2945.html
 */
ProcessMonitor::ProcessMonitor() : mSocket(0), mListen(false), mValid(false)
{
    mPageSize = sysconf(_SC_PAGESIZE);

    mSocket = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_CONNECTOR);
    if (mSocket < 0)
    {
        Log("Failed to open netlink socket");
        return;
    }

    struct sockaddr_nl sa = {};
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = CN_IDX_PROC;
    sa.nl_pid = getpid();

    if (bind(mSocket, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        Log("Failed to bind netlink socket with error '%s'", strerror(errno));
        close(mSocket);
        mSocket = 0;
        return;
    }

    setSocketFilter();

    mValid = true;
}

ProcessMonitor::~ProcessMonitor()
{
    if (mListen)
    {
        Stop();
    }

    if (mSocket > 0)
    {
        if (close(mSocket) < 0)
        {
            Log("Failed to close socket with error '%s'", strerror(errno));
        }
    }
}

/**
 * @brief Start a thread to capture process exec/exit. Returns as soon as thread started, non-blocking
 *
 * @return True if capture thread started
 */
bool ProcessMonitor::Start()
{
    if (mValid)
    {
        mStart = std::chrono::system_clock::now();
        mListen = setListenMode(true);

        if (mListen)
        {
            mMessageReceiver = std::thread(&ProcessMonitor::receiveMessages, this);

            return mMessageReceiver.joinable();
        }
        return false;
    }

    return false;
}

/**
 * Stop the currently running capture thread
 *
 * @return True if successfully stopped
 */
bool ProcessMonitor::Stop()
{
    mListen = false;
    mEnd = std::chrono::system_clock::now();
    if (mMessageReceiver.joinable())
    {
        mMessageReceiver.join();
    }

    setListenMode(false);

    return true;
}

/**
 * @brief Enables kernel-level filtering on the socket with BPF to reduce userspace CPU load by only receiving
 * events we actually care about
 */
void ProcessMonitor::setSocketFilter() const
{
    // Best practice is to block everything first, then drain the socket completely. This prevents unwanted events
    // making it through whilst we're building and applying our filter
    // https://natanyellin.com/posts/ebpf-filtering-done-right/

    // Start by blocking all events
    struct sock_filter blockAll[] = {
        BPF_STMT(OP_RET, BPF_DENY),
    };

    struct sock_fprog blockAllProgram = {.len = 1, .filter = blockAll};

    if (setsockopt(mSocket, SOL_SOCKET, SO_ATTACH_FILTER, &blockAllProgram, sizeof blockAllProgram) < 0)
    {
        Log("Failed to set socket options with error %s", strerror(errno));
    }

    // Drain the socket
    char dummy[1];
    while (true)
    {
        ssize_t bytes = recv(mSocket, dummy, sizeof(dummy), MSG_DONTWAIT);
        if (bytes == -1)
        {
            break;
        }
    }

    // Write the actual filter we want to apply
    // This BPF filter allows exec/exit messages through only
    struct sock_filter processFilter[] =
        {BPF_STMT(OP_LDH, offsetof(struct nlmsghdr, nlmsg_type)),
         BPF_JUMP(OP_JEQ, htons(NLMSG_DONE), 1, 0), // Only allow complete netlink messages (block noop, error etc)
         BPF_STMT(OP_RET, BPF_DENY),
         BPF_STMT(OP_LDW, NLMSG_LENGTH(0) + offsetof(struct cn_msg, id) + offsetof(struct cb_id, idx)),
         BPF_JUMP(OP_JEQ, htonl(CN_IDX_PROC | CN_VAL_PROC), 1, 0), // Only allow messages from the process communicator
         BPF_STMT(OP_RET, BPF_DENY),
         BPF_STMT(OP_LDW, NLMSG_LENGTH(0) + offsetof(struct cn_msg, data) + offsetof(struct proc_event, what)),
         BPF_JUMP(OP_JEQ, htonl(proc_event::PROC_EVENT_EXEC), 2, 0), // Only allow exec/exit
         BPF_JUMP(OP_JEQ, htonl(proc_event::PROC_EVENT_EXIT), 1, 0),
         BPF_STMT(OP_RET, BPF_DENY),
         BPF_STMT(OP_RET, BPF_ALLOW)};

    struct sock_fprog processFilterProgram = {};
    processFilterProgram.len = sizeof processFilter / sizeof processFilter[0];
    processFilterProgram.filter = processFilter;

    if (setsockopt(mSocket, SOL_SOCKET, SO_ATTACH_FILTER, &processFilterProgram, sizeof processFilterProgram) < 0)
    {
        Log("Failed to set socket options with error %s", strerror(errno));
    }
}

/**
 * Sets the listening mode on the netlink socket to start/stop receiving events
 *
 * @param enable Whether to receive events over the netlink socket
 *
 * @return True if the listen mode was set successfully
 */
bool ProcessMonitor::setListenMode(bool enable) const
{
    struct iovec iov[3];

    char messageBuffer[NLMSG_LENGTH(0)];

    auto *messageHeader = reinterpret_cast<nlmsghdr *>(messageBuffer);
    struct cn_msg connectorMessage = {};
    enum proc_cn_mcast_op op;

    messageHeader->nlmsg_len = NLMSG_LENGTH(sizeof(connectorMessage) + sizeof(op));
    messageHeader->nlmsg_type = NLMSG_DONE;
    messageHeader->nlmsg_flags = 0;
    messageHeader->nlmsg_seq = 0;
    messageHeader->nlmsg_pid = getpid();

    iov[0].iov_base = messageBuffer;
    iov[0].iov_len = NLMSG_LENGTH(0);

    connectorMessage.id.idx = CN_IDX_PROC;
    connectorMessage.id.val = CN_VAL_PROC;
    connectorMessage.seq = 0;
    connectorMessage.ack = 0;
    connectorMessage.len = sizeof op;

    iov[1].iov_base = &connectorMessage;
    iov[1].iov_len = sizeof connectorMessage;

    if (enable)
    {
        op = PROC_CN_MCAST_LISTEN;
    }
    else
    {
        op = PROC_CN_MCAST_IGNORE;
    }

    iov[2].iov_base = &op;
    iov[2].iov_len = sizeof(op);

    if (writev(mSocket, iov, 3) < 0)
    {
        Log("Failed to set listen mode to %d with error '%s'", enable, strerror(errno));
        return false;
    }
    else
    {
        return true;
    }
}

/**
 * Loop to process incoming netlink messages and track process exec/exit
 */
void ProcessMonitor::receiveMessages()
{
    char buffer[mPageSize];

    struct msghdr header = {};
    struct sockaddr_nl address = {};

    struct iovec iov[1];
    iov[0].iov_base = buffer;
    iov[0].iov_len = sizeof buffer;

    header.msg_name = &address;
    header.msg_namelen = sizeof address;
    header.msg_iov = iov;
    header.msg_iovlen = 1;
    header.msg_control = nullptr;
    header.msg_controllen = 0;
    header.msg_flags = 0;

    while (mListen)
    {
        ssize_t len = TEMP_FAILURE_RETRY(recvmsg(mSocket, &header, 0));

        if (len < 0)
        {
            Log("Failed to receive message with error %d", errno);
        }

        if (address.nl_pid != 0)
        {
            continue;
        }

        // Got a message
        for (auto *message = reinterpret_cast<struct nlmsghdr *>(buffer); NLMSG_OK(message, len);
             message = NLMSG_NEXT(message, len))
        {
            auto *connectorMessage = static_cast<cn_msg *>(NLMSG_DATA(message));

            // We shouldn't need to worry about this anymore, since we filter with BPF but keep just in case I've
            // messed up the bpf filter
            if (connectorMessage->id.idx != CN_IDX_PROC || connectorMessage->id.val != CN_VAL_PROC)
            {
                // Ignore messages not from the connector subsystem
                continue;
            }

            // Got something we actually care about
            auto *ev = reinterpret_cast<struct proc_event *>(connectorMessage->data);

            switch (ev->what)
            {
            case proc_event::PROC_EVENT_EXEC:
            {
                // Process has started
                processInfo info{};

                info.pid = ev->event_data.exec.process_pid;
                info.parentPid = getParentPid(info.pid);
                info.grandparentPid = getParentPid(info.parentPid);

                // This isn't going to be 100% accurate but close enough
                info.startTime = std::chrono::system_clock::now();

                getProcessCommandLine(info.pid, info.commandLine);
                getProcessCommandLine(info.parentPid, info.parentCommandLine);
                getProcessCommandLine(info.grandparentPid, info.grandparentCommandLine);

                info.systemdServiceName = getSystemdService(info.pid);

                mRunningProcesses.emplace_back(info);
                break;
            }
            case proc_event::PROC_EVENT_EXIT:
            {
                // Process has exited

                pid_t pid = ev->event_data.exit.process_pid;

                auto process = std::find_if(mRunningProcesses.begin(), mRunningProcesses.end(),
                                            [pid](const processInfo &pi) { return pi.pid == pid; });

                // Are we tracking this process?
                if (process != mRunningProcesses.end())
                {
                    auto &p = (*process);

                    // Update process with the exit time and code
                    p.endTime = std::chrono::system_clock::now();
                    p.exitCode = ev->event_data.exit.exit_code;

                    // Move process from running vector to exited vector
                    mExitedProcesses.insert(mExitedProcesses.end(), std::make_move_iterator(process),
                                            std::make_move_iterator(std::next(process)));
                    mRunningProcesses.erase(process);
                }

                break;
            }
            default:
                break;
            }
        }
    }
}

/**
 * Given a PID, retrieve the command line of the processes from /proc/x/cmdline, correctly parsing it into a std string
 *
 * Commandline will be "Unknown" if this fails - can happen for extremely short-lived processes that have quit by the
 * time we get here
 *
 * @param pid PID to get command line for
 * @param[out] commandLine command line of the process.
 */
void ProcessMonitor::getProcessCommandLine(pid_t pid, std::string &commandLine)
{
    char procPath[PATH_MAX];

    sprintf(procPath, "/proc/%u/cmdline", pid);

    int fd = open(procPath, O_CLOEXEC | O_RDONLY);
    if (fd > 0)
    {
        char cmdline[PATH_MAX];

        ssize_t ret = read(fd, cmdline, PATH_MAX);
        if (ret > 0)
        {
            // Command line contains full string with args
            commandLine.assign(cmdline, ret);

            // Replace null chars with spaces
            std::replace(commandLine.begin(), std::prev(commandLine.end()), '\0', ' ');
            commandLine.erase(std::remove(std::prev(commandLine.end()), commandLine.end(), '\0'), commandLine.end());
        }
        else
        {
            // Failed to read from file, process has probably quit
            commandLine = "Unknown";
        }

        close(fd);
    }
    else
    {
        // Can't read cmdline file, process has probably quit
        commandLine = "Unknown";
    }
}

/**
 * Given a PID, return the PID of the parent process
 *
 * @param pid PID to find parent pid of
 * @return parent pid - 0 if unknown
 */
pid_t ProcessMonitor::getParentPid(pid_t pid)
{
    char procPath[PATH_MAX];

    sprintf(procPath, "/proc/%u/stat", pid);

    FILE *f = fopen(procPath, "r");
    if (f != nullptr)
    {
        pid_t parentPid;
        if (fscanf(f, "%*d %*s %*c %d", &parentPid) > 0)
        {
            fclose(f);
            return parentPid;
        }
        else
        {
            return 0;
        }
    }

    return 0;
}

/**
 * Build a JSON document containing the results, formatted in a suitable way for a vis.js dataset that can be displayed
 * in a timeline
 *
 * @return JSON string
 */
std::string ProcessMonitor::GetJson()
{
    Log("Generating process JSON");

    // Convert this into a form that vis.js timeline can understand
    nlohmann::json results;

    std::set<std::string> groups;
    std::set<std::string> systemdServices;

    nlohmann::json process;
    std::map<std::string, int> processExecutionCount;

    std::unordered_map<std::string, int> systemdServiceCount;

    for (auto &p : mExitedProcesses)
    {
        if (!p.commandLine.empty() && p.commandLine != "Unknown" && !p.parentCommandLine.empty() &&
            p.parentCommandLine != "Unknown")
        {
            process.clear();

            // Can't just use PID on its own as the id, since Linux will re-use PIDs eventually
            // Instead, id is built from start time and pid
            process["id"] = std::to_string(p.pid) + "_" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(p.startTime.time_since_epoch()).count());
            process["pid"] = p.pid;
            process["content"] = p.GetStrippedName();
            process["title"] = p.GetStrippedCommandLine();
            process["group"] = p.GetGroupName();
            process["start"] =
                std::chrono::duration_cast<std::chrono::milliseconds>(p.startTime.time_since_epoch()).count();
            process["end"] = std::chrono::duration_cast<std::chrono::milliseconds>(p.endTime.time_since_epoch()).count();
            process["fullCommandLine"] = p.commandLine;
            process["parentCommandLine"] = p.parentCommandLine;
            process["grandparentCommandLine"] = p.grandparentCommandLine;
            process["exitCode"] = p.exitCode;
            process["systemdService"] = p.systemdServiceName;

            results["processes"].emplace_back(process);

            groups.insert(process["group"]);
            systemdServices.insert(p.systemdServiceName);

            processExecutionCount[p.GetStrippedName()] += 1;

            systemdServiceCount[p.systemdServiceName] += 1;
        }
    }

    for (const auto &g : groups)
    {
        nlohmann::json group;
        group["id"] = g;
        group["content"] = g;

        results["groups"].emplace_back(group);
    }

    for (const auto &freq : processExecutionCount)
    {
        nlohmann::json stats;
        stats["process"] = freq.first;
        stats["frequency"] = freq.second;

        results["stats"]["processes"].emplace_back(stats);
    }

    for (const auto &service : systemdServiceCount)
    {
        nlohmann::json stats;
        stats["serviceName"] = service.first;
        stats["frequency"] = service.second;

        results["stats"]["services"].emplace_back(stats);
    }

    results["start"] = std::chrono::duration_cast<std::chrono::milliseconds>(mStart.time_since_epoch()).count();
    results["end"] = std::chrono::duration_cast<std::chrono::milliseconds>(mEnd.time_since_epoch()).count();

    return results.dump();
}

/**
 * Given a PID, attempts to work out which systemd service it belongs to
 *
 * Will return "None" if it does not belong to a service
 * @param pid
 * @return
 */
std::string ProcessMonitor::getSystemdService(pid_t pid)
{
    char cgroupPath[PATH_MAX]{};
    sprintf(cgroupPath, "/proc/%u/cgroup", pid);

    std::ifstream cgroupFile(cgroupPath);

    if (!cgroupFile)
    {
        return "None";
    }

    std::string line;
    char serviceName[256]{};
    while (std::getline(cgroupFile, line))
    {
        // Example: 1:name=systemd:/system.slice/ip-setup-monitor.service
        if (sscanf(line.c_str(), "%*d:name=systemd:/system.slice/%255s", serviceName) > 0)
        {
            return {serviceName};
        }
    }

    return "None";
}
