cmake_minimum_required(VERSION 3.16.0)

# Project version
set(MAJOR_VERSION 1)
set(MINOR_VERSION 0)
set(PATCH_VERSION 0)

project(ProcessMonitor VERSION "${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}")

# Include GNUInstallDirs module to access CMAKE_INSTALL_* directory variables
include(GNUInstallDirs)

# Add our local cmake directory to search for components
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_LIST_DIR}/cmake")

# Enable C++17 support.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable warnings
add_compile_options(-Wall)

# Disables an annoying warning "<blah> will change in GCC X.XX"
add_compile_options(-Wno-psabi)

find_package(Threads)

add_executable(${PROJECT_NAME}
        main.cpp
        ProcessMonitor.cpp
        )

target_include_directories(${PROJECT_NAME}
        PRIVATE
        ./third_party
        )

target_link_libraries(${PROJECT_NAME}
        Threads::Threads)

install(TARGETS ${PROJECT_NAME}
        RUNTIME DESTINATION bin
        )