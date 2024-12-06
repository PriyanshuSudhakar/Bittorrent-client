cmake_minimum_required(VERSION 3.13)

project(bittorrent-starter-cpp)

file(GLOB_RECURSE SOURCE_FILES src/*.cpp src/*.hpp)

set(CMAKE_CXX_STANDARD 23) # Enable the C++23 standard

# Add the `lib/` directory to the include directories
# include_directories(${CMAKE_SOURCE_DIR}/lib)

file(GLOB_RECURSE SOURCE_FILES src/*.hpp  lib/sha1.hpp)

add_executable(bittorrent ${SOURCE_FILES})

