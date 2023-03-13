// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Stephen Foulds

#pragma once

#include <chrono>
#include <regex>
#include <string>
#include <vector>

/**
 * Often commands will be prefixed with the interpreter to use (e.g. /bin/sh -c echo "hello world"). Strip
 * these off to reveal the "true" command
 */
static std::vector<std::string> prefixesToStrip =
    {"/bin/sh -c ", "/bin/sh ",           "/bin/bash -c ",    "/bin/bash ",        "sh -c",
     "sh ",         "/bin/busybox sh -c", "/bin/busybox sh ", "/bin/busybox bash "};

static std::regex envVarRegex(R"(^[A-Z_]+=(`.*`|\$\(.*\)|[\w\/\${}:]+);?)");

struct processInfo
{
    pid_t pid;
    pid_t parentPid;
    pid_t grandparentPid;

    std::chrono::time_point<std::chrono::system_clock> endTime;
    std::chrono::time_point<std::chrono::system_clock> startTime;

    uint32_t exitCode;

    std::string commandLine;
    std::string parentCommandLine;
    std::string grandparentCommandLine;

    std::string systemdServiceName;

    /**
     * Use some heuristics to try and get a suitable name for the timeline group
     *
     * @return
     */
    [[nodiscard]] std::string GetGroupName()
    {
        if (GetStrippedParentName().empty())
        {
            return GetStrippedGrandparentName();
        }

        /*       for (const auto& prefix : prefixesToStrip)
               {
                   if (parentCommandLine.rfind(prefix, 0) == 0)
                   {
                       return GetStrippedGrandparentName();
                   }
               }*/

        return GetStrippedParentName();
    }

    [[nodiscard]] std::string GetName() { return GetNameFromCommandLine(commandLine); }

    /**
     * Get the name of the process, with any leading interpreter removed
     *
     * Removes any arguments passed to the process, just leaving the name of the process (including directory)
     *
     * Examples:
     *  * "/bin/sh -c ls" becomes "ls"
     *  * "ls -alh" becomes "ls"
     *  * "/lib/rdk/script.sh --foo --bar" becomes "/lib/rdk/script.sh"
     *
     * @return stripped process name string
     */
    [[nodiscard]] std::string GetStrippedName()
    {
        if (mStrippedName.empty())
        {
            mStrippedName = GetNameFromCommandLine(GetStrippedCommandLine());
        }

        return mStrippedName;
    }

    /**
     * Get the command line of the process, with any leading interpreter removed
     *
     * Examples:
     *  * "/bin/sh -c ls -alh" becomes "ls -alh"
     *  * "ls -alh" becomes "ls -alh"
     *  * "/lib/rdk/script.sh --foo --bar" becomes "/lib/rdk/script.sh --foo --bar"
     *
     * @return stripped process command line string
     */
    [[nodiscard]] std::string GetStrippedCommandLine()
    {
        if (mStrippedCmdline.empty())
        {
            mStrippedCmdline = StripPrefix(commandLine);
        }
        return mStrippedCmdline;
    }

    /**
     * Get the name of the parent process, with any leading interpreter removed
     *
     * @return stripped parent process name
     */
    [[nodiscard]] std::string GetStrippedParentName()
    {
        if (mStrippedParentName.empty())
        {
            mStrippedParentName = GetNameFromCommandLine(GetStrippedParentCommandLine());
        }
        return mStrippedParentName;
    }

    /**
     * Get the name of the grandparent process if possible, with any leading interpreter removed
     *
     * @return stripped grandparent process name
     */
    [[nodiscard]] std::string GetStrippedGrandparentName()
    {
        if (mStrippedGrandparentName.empty())
        {
            mStrippedGrandparentName = GetNameFromCommandLine(GetStrippedGrandparentCommandLine());
        }
        return mStrippedGrandparentName;
    }

    /**
     * Get the command line of the grandparent process, with any leading interpreter removed
     *
     * @return stripped grandparent command line string
     */
    [[nodiscard]] std::string GetStrippedParentCommandLine()
    {
        if (mStrippedParentCmdline.empty())
        {
            mStrippedParentCmdline = StripPrefix(parentCommandLine);
        }
        return mStrippedParentCmdline;
    }

    /**
     * Get the command line of the parent process, with any leading interpreter removed
     *
     * @return stripped parent command line string
     */
    [[nodiscard]] std::string GetStrippedGrandparentCommandLine()
    {
        if (mStrippedGrandparentCmdline.empty())
        {
            mStrippedGrandparentCmdline = StripPrefix(grandparentCommandLine);
        }
        return mStrippedGrandparentCmdline;
    }

private:
    /**
     * Remove the interpreter prefix from a given process commandline
     *
     * @param cmdline
     * @return
     */
    [[nodiscard]] static std::string StripPrefix(const std::string &cmdline)
    {
        for (const auto &prefix : prefixesToStrip)
        {
            if (/*cmdline.length() > prefix.length() && */ cmdline.rfind(prefix, 0) == 0)
            {
                auto tmp = cmdline;
                tmp.erase(tmp.begin(), tmp.begin() + prefix.size());

                if (tmp[0] == ' ')
                {
                    tmp.erase(0, 1);
                }

                return tmp;
            }
        }

        return cmdline;
    }

    /**
     * Attempts to work out the name of the process, given a full command line.
     *
     * This will return the first part of a given path, removing any arguments supplied
     *
     * E.G
     *  * "/bin/ls -alh" becomes "/bin/ls"
     *  * "/bin/sh -c ls -alh" becomes "/bin/sh"
     *
     * You might want to strip the provided command line of any prefix before passing it to this function to get
     * a more accurate name
     *
     * @param commandLine
     * @return
     */
    [[nodiscard]] static std::string GetNameFromCommandLine(const std::string &commandLine)
    {
        std::string name = commandLine;
        // Remove any leading spaces
        if (name[0] == ' ')
        {
            name.erase(0, 1);
        }

        // Remove environment variable(s)
        name = std::regex_replace(name, envVarRegex, "");

        if (name[0] == ' ')
        {
            name.erase(0, 1);
        }

        // First the first space - name is everything before that
        auto spacePos = name.find_first_of(' ');
        if (spacePos != std::string::npos)
        {
            auto it = name.begin();
            std::advance(it, spacePos);
            name.erase(it, name.end());
        }

        return name;
    }

    std::string mStrippedName;
    std::string mStrippedParentName;
    std::string mStrippedGrandparentName;

    std::string mStrippedCmdline;
    std::string mStrippedParentCmdline;
    std::string mStrippedGrandparentCmdline;
};
