cmake_minimum_required(VERSION 3.10)

project(Argon2 VERSION 1.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include_directories(./Argon2 ./Blake2)

file(GLOB SOURCES "./Blake2/blake2b.c" "./Argon2/argon2.cpp" "./Argon2/argon2-core.cpp" "./Argon2/argon2-opt-core.cpp" "./Argon2/kat.cpp")

add_library(argon2 STATIC ${SOURCES})
