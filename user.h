#pragma once

#include <string>

struct User {
    std::string username;
    bool isAdmin = false;
    std::string registrationTime;
    std::string lastLoginTime;
};
