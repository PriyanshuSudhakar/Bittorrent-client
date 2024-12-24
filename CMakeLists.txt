cmake_minimum_required(VERSION 3.13)

project(bittorrent-starter-cpp)

file(GLOB_RECURSE SOURCE_FILES src/*.cpp src/*.hpp)

find_package(CURL REQUIRED)
add_executable(bittorrent src/Main.cpp)
target_link_libraries(bittorrent ${CURL_LIBRARIES})

set(CMAKE_CXX_STANDARD 23) # Enable the C++23 standard

add_executable(bittorrent ${SOURCE_FILES})

