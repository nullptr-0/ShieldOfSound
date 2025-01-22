cmake_minimum_required(VERSION 3.10)

project(base64 VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include_directories(.)

file(GLOB SOURCES "base64.cpp")

add_library(base64 STATIC ${SOURCES})
