// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Stephen Foulds

#include "ProcessMonitor.h"

#include <condition_variable>
#include <csignal>
#include <getopt.h>
#include <mutex>
#include <filesystem>
#include <fstream>

#include "Log.h"

std::mutex gMutex;
std::condition_variable gShutdown;

static std::string gOutputFile;

// Default to 30 seconds
static int gDurationSeconds = 30;

/**
 * @brief Display a help message for the tool
 */
static void displayUsage()
{
    printf("Usage: ProcessMonitor <option(s)>\n");
    printf("    Linux process monitor\n\n");
    printf("    -h, --help          Print this help and exit\n");
    printf("    -d, --duration      How long to capture data for (seconds)\n");
    printf("    -o  --output        File to save results to\n");
}

/**
 * @brief Parse the provided command line arguments
 */
static void parseArgs(const int argc, char **argv)
{
    struct option longopts[] = {{"help", no_argument, nullptr, (int)'h'},
                                {"duration", required_argument, nullptr, (int)'d'},
                                {"output", required_argument, nullptr, (int)'o'},
                                {nullptr, 0, nullptr, 0}};

    opterr = 0;

    int option;
    int longindex;

    while ((option = getopt_long(argc, argv, "hd:o:", longopts, &longindex)) != -1)
    {
        switch (option)
        {
        case 'h':
            displayUsage();
            exit(EXIT_SUCCESS);
            break;
        case 'd':
            gDurationSeconds = std::atoi(optarg);
            if (gDurationSeconds < 0)
            {
                fprintf(stderr, "Error: Duration must be > 0\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'o':
            gOutputFile = std::string(optarg);
            break;
        case '?':
            if (optopt == 'c')
                fprintf(stderr, "Warning: Option -%c requires an argument.\n", optopt);
            else if (isprint(optopt))
                fprintf(stderr, "Warning: Unknown option `-%c'.\n", optopt);
            else
                fprintf(stderr, "Warning: Unknown option character `\\x%x'.\n", optopt);

            exit(EXIT_FAILURE);
            break;
        default:
            exit(EXIT_FAILURE);
            break;
        }
    }

    for (int i = optind; i < argc; i++)
    {
        printf("Warning: Non-option argument %s ignored\n", argv[i]);
    }
}

void signalHandler([[maybe_unused]] int signal)
{
    Log("Shutting down");
    gShutdown.notify_all();
}

int main(int argc, char **argv)
{
    // Parse arguments
    parseArgs(argc, argv);

    if (gOutputFile.empty())
    {
        fprintf(stderr, "Error: Must provide output file\n");
        return EXIT_FAILURE;
    }


    Log("Output file: %s", gOutputFile.c_str());
    Log("Capture duration: %d seconds", gDurationSeconds);

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    // Start tracking events
    ProcessMonitor monitor;
    if (!monitor.Start())
    {
        return EXIT_FAILURE;
    }

    Log("Listening for process events");

    // Wait for shutdown signal or duration complete
    std::unique_lock<std::mutex> lock(gMutex);
    gShutdown.wait_for(lock, std::chrono::seconds(gDurationSeconds));

    monitor.Stop();

    auto json = monitor.GetJson();

    auto outputFile = std::filesystem::path(gOutputFile);
    auto outputDirectory = outputFile.parent_path();

    // Create directory if it doesn't exist
    if (!std::filesystem::exists(outputDirectory))
    {
        std::filesystem::create_directory(outputDirectory);
    }

    Log("Saving results to %s", gOutputFile.c_str());

    // Write results
    std::ofstream outputStream(outputFile);
    if (outputStream)
    {
        outputStream << "let results = " << json << ";";
        return EXIT_SUCCESS;
    }
    else
    {
        Log("Failed to write to output file %s", gOutputFile.c_str());
        return EXIT_FAILURE;
    }
}
