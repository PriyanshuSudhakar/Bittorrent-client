cmake_minimum_required(VERSION 3.13)

project(bittorrent-starter-cpp)

# Collect all source files recursively
file(GLOB_RECURSE SOURCE_FILES src/*.cpp src/*.hpp)

# Set C++ standard to C++23
set(CMAKE_CXX_STANDARD 23)

# Add executable target
add_executable(bittorrent ${SOURCE_FILES})

# Include curl headers
include_directories(src/lib/curl)

# Link the executable with libcurl
target_link_libraries(bittorrent curl)
