#include "ProcessMonitor.h"

#include <condition_variable>
#include <csignal>
#include <mutex>

#include "Log.h"

std::mutex gMutex;
std::condition_variable gShutdown;

void signalHandler([[maybe_unused]] int signal)
{
    Log("Shutting down");
    gShutdown.notify_all();
}

int main(int argc, char** argv)
{
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    ProcessMonitor monitor;
    if (!monitor.Start())
    {
        return EXIT_FAILURE;
    }

    Log("Listening for process events");
    // Wait for shutdown signal
    std::unique_lock<std::mutex> lock(gMutex);
    gShutdown.wait(lock);

    monitor.Stop();

    auto json = monitor.GetJson();
    printf("let results = %s;", json.c_str());

    return EXIT_SUCCESS;
}
