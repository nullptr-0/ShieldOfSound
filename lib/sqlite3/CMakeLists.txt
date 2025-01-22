cmake_minimum_required(VERSION 3.10)

project(sqlite3 VERSION 1.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include_directories(.)

file(GLOB SOURCES "./*.c")

add_library(sqlite3 STATIC ${SOURCES})
