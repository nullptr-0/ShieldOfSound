#pragma once

#ifndef NETUTIL_HPP
#define NETUTIL_HPP

#include <string>
#include <unordered_map>
#include <sstream>
#include <algorithm>
#include <cctype>

// Helper function to trim whitespace from the beginning and end of a string
std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(' ');
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, last - first + 1);
}

// Function to parse cookies from a cookie string
std::unordered_map<std::string, std::string> parseCookies(const std::string& cookieString) {
    std::unordered_map<std::string, std::string> cookies;
    std::istringstream cookieStream(cookieString);
    std::string cookiePair;

    while (std::getline(cookieStream, cookiePair, ';')) {
        // Split the cookie pair into key and value by '='
        size_t pos = cookiePair.find('=');
        if (pos != std::string::npos) {
            std::string key = trim(cookiePair.substr(0, pos));
            std::string value = trim(cookiePair.substr(pos + 1));
            cookies[key] = value;
        }
    }

    return cookies;
}

// Helper function to decode URL-encoded strings
std::string urlDecode(const std::string& str) {
    std::string decoded;
    char hexBuffer[3] = { 0 };

    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '%') {
            if (i + 2 < str.length()) {
                hexBuffer[0] = str[i + 1];
                hexBuffer[1] = str[i + 2];
                decoded += static_cast<char>(std::strtol(hexBuffer, nullptr, 16));
                i += 2;
            }
        }
        else if (str[i] == '+') {
            decoded += ' '; // '+' in URL encoding is a space
        }
        else {
            decoded += str[i];
        }
    }

    return decoded;
}

// Helper function to split form data into key-value pairs
std::unordered_map<std::string, std::string> parseFormData(const std::string& formData) {
    std::unordered_map<std::string, std::string> formMap;
    std::istringstream formStream(formData);
    std::string pair;

    // Split the form data by '&' to get key-value pairs
    while (std::getline(formStream, pair, '&')) {
        size_t pos = pair.find('=');
        if (pos != std::string::npos) {
            std::string key = urlDecode(pair.substr(0, pos));
            std::string value = urlDecode(pair.substr(pos + 1));
            formMap[key] = value;
        }
    }

    return formMap;
}

#endif // !NETUTIL_HPP
