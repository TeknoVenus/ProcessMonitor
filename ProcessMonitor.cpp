//
// Created by Stephen F on 09/02/23.
//

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
ProcessMonitor::ProcessMonitor()
    : mSocket(0), mListen(false), mValid(false),
      mStripPrefixes({"/bin/sh -c ", "/bin/sh ", "/bin/bash ", "sh -c", "sh ", "/bin/busybox sh -c", "/bin/busybox sh ",
                      "/bin/busybox bash "})
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

bool ProcessMonitor::Start()
{
    if (mValid)
    {
        mStart = std::chrono::system_clock::now();
        mListen = setListenMode(true);
        mMessageReceiver = std::thread(&ProcessMonitor::receiveMessages, this);

        return mListen;
    }

    return false;
}

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

void ProcessMonitor::receiveMessages()
{
    struct msghdr header = {};
    struct sockaddr_nl addr = {};
    struct iovec iov[1];

    char buf[mPageSize];
    ssize_t len;

    header.msg_name = &addr;
    header.msg_namelen = sizeof addr;
    header.msg_iov = iov;
    header.msg_iovlen = 1;
    header.msg_control = nullptr;
    header.msg_controllen = 0;
    header.msg_flags = 0;

    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof buf;

    while (mListen)
    {
        len = recvmsg(mSocket, &header, 0);

        if (addr.nl_pid != 0)
        {
            continue;
        }

        // Got a message
        for (auto *message = reinterpret_cast<struct nlmsghdr *>(buf); NLMSG_OK(message, len);
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
                processInfo info = {};

                info.pid = ev->event_data.exec.process_pid;
                info.parentPid = getParentPid(info.pid);

                info.startTime = std::chrono::system_clock::now();

                getProcessName(info.pid, info.name, info.commandLine);
                getProcessName(info.parentPid, info.parentName, info.parentCommandLine);

                mRunningProcesses.emplace_back(info);
                break;
            }
            case proc_event::PROC_EVENT_EXIT:
            {
                pid_t pid = ev->event_data.exit.process_pid;
                auto process = std::find_if(mRunningProcesses.begin(), mRunningProcesses.end(),
                                            [pid](const processInfo &pi) { return pi.pid == pid; });

                if (process != mRunningProcesses.end())
                {
                    auto &p = (*process);

                    p.endTime = std::chrono::system_clock::now();
                    p.exitCode = ev->event_data.exit.exit_code;

                    // Log("Process '%s' (%s) (PID %d) exited with code %d (parent %s pid:%d)", p.name.c_str(),
                    // p.commandLine.c_str(), p.pid,
                    //                        p.exitCode, p.parentName.c_str(), p.parentPid);

                    // Move process from running to exited
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

void ProcessMonitor::getProcessName(pid_t pid, std::string &name, std::string &commandLine) const
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
            // Name is just the main process name
            commandLine.assign(cmdline, ret);

            // Remove null chars
            std::replace(commandLine.begin(), std::prev(commandLine.end()), '\0', ' ');
            commandLine.erase(std::remove(std::prev(commandLine.end()), commandLine.end(), '\0'), commandLine.end());

            // To make our life easier, remove /bin/sh or similar from the start of the command if it's present
            for (const auto &prefix : mStripPrefixes)
            {
                if (commandLine.rfind(prefix, 0) == 0)
                {
                    commandLine.erase(commandLine.begin(), commandLine.begin() + prefix.size());
                    break;
                }
            }

            name = commandLine;
            if (name[0] == ' ')
            {
                name.erase(0, 1);
            }

            auto spacePos = name.find_first_of(' ');
            if (spacePos != std::string::npos)
            {
                auto it = name.begin();
                std::advance(it, spacePos);
                name.erase(it, name.end());
            }
        }
        else
        {
            name = "Unknown";
            commandLine = "Unknown";
        }

        close(fd);
    }
    else
    {
        name = "Unknown";
        commandLine = "Unknown";
    }
}

pid_t ProcessMonitor::getParentPid(pid_t pid) const
{
    char procPath[PATH_MAX];

    sprintf(procPath, "/proc/%u/status", pid);

    FILE *f = fopen(procPath, "r");
    if (f != nullptr)
    {
        char buffer[1024];
        pid_t parentPid;
        while (fgets(buffer, sizeof(buffer), f) != nullptr)
        {
            if (sscanf(buffer, "PPid:\t%d", &parentPid) != 0)
            {
                break;
            }
        }

        fclose(f);
        return parentPid;
    }

    return 0;
}

std::string ProcessMonitor::GetJson()
{
    Log("Generating process JSON");

    // Convert this into a form that vis.js timeline can understand
    nlohmann::json results;

    std::set<std::string> groups;

    nlohmann::json process;
    std::map<std::string, int> processExecutionCount;
    for (const auto &p : mExitedProcesses)
    {
        if (!p.name.empty() && p.name != "Unknown" && !p.parentName.empty() && p.parentName != "Unknown")
        {
            process.clear();
            process["id"] = p.pid;
            process["content"] = p.name;
            process["title"] = p.commandLine;
            process["group"] = p.parentName;
            process["start"] =
                std::chrono::duration_cast<std::chrono::milliseconds>(p.startTime.time_since_epoch()).count();
            process["end"] = std::chrono::duration_cast<std::chrono::milliseconds>(p.endTime.time_since_epoch()).count();
            results["processes"].emplace_back(process);

            groups.insert(p.parentName);

            processExecutionCount[p.name] += 1;
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
        results["stats"].emplace_back(stats);
    }

    results["start"] = std::chrono::duration_cast<std::chrono::milliseconds>(mStart.time_since_epoch()).count();
    results["end"] = std::chrono::duration_cast<std::chrono::milliseconds>(mEnd.time_since_epoch()).count();

    return results.dump();
}
