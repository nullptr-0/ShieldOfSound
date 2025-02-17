cmake_minimum_required(VERSION 3.10)
project(ShieldOfSound)

set(CMAKE_CXX_STANDARD 20)

# Argon2
add_subdirectory(lib/argon2)
include_directories(lib/argon2)
#link_directories(lib/argon2)

# Boost
add_subdirectory(lib/boost)
include_directories(lib/boost)
#link_directories(lib/boost)

# cpp-httplib
include_directories(lib/httplib)

# json
include_directories(lib/json)

# SQLite
add_subdirectory(lib/sqlite3)
include_directories(lib/sqlite3)
#link_directories(lib/sqlite3)

# Mbed TLS
add_subdirectory(lib/mbedtls)
include_directories(lib/mbedtls/include)
#link_directories(lib/mbedtls)

add_executable(server main.cpp userdb.cpp session.cpp filedb.cpp)
target_link_libraries(server argon2 base64 sqlite3 mbedcrypto)
