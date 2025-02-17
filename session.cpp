#include "session.h"
#include <random>
#include <chrono>
#include <algorithm>

std::string SessionManager::generateSessionId() {
    std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string sessionId;
    std::default_random_engine generator(std::chrono::system_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<int> distribution(0, chars.size() - 1);

    for (int i = 0; i < 32; ++i) {
        sessionId += chars[distribution(generator)];
    }
    return sessionId;
}

std::string SessionManager::createSession(const std::string& username, uint32_t timeoutSeconds) {
    std::string sessionId = generateSessionId();
    sessions[sessionId].username = username;
    sessions[sessionId].timeoutSeconds = timeoutSeconds;
    userSessions[username].push_back(sessionId);
    updateSession(sessionId);
    return sessionId;
}

bool SessionManager::isValidSession(const std::string& sessionId) {
    auto it = sessions.find(sessionId);
    if (it != sessions.end()) {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.lastActivity).count();
        return duration < it->second.timeoutSeconds;
    }
    return false;
}

void SessionManager::updateSession(const std::string& sessionId) {
    sessions[sessionId].lastActivity = std::chrono::steady_clock::now();
}

void SessionManager::destroyUserSessions(const std::string& username) {
    auto& userSessionsVec = userSessions[username];
    for (auto& sessionId : userSessionsVec) {
        sessions.erase(sessionId);
    }
    userSessions.erase(username);
}

void SessionManager::destroySession(const std::string& sessionId) {
    sessions.erase(sessionId);
    auto& userSessionsVec = userSessions[getUsername(sessionId)];
    auto sessionToErase = std::find(userSessionsVec.begin(), userSessionsVec.end(), sessionId);
    if (sessionToErase != userSessionsVec.end()) {
        userSessionsVec.erase(sessionToErase);
    }
}

std::string SessionManager::getUsername(const std::string& sessionId) {
    return sessions[sessionId].username;
}

void SessionManager::clearExpiredSessions() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = sessions.begin(); it != sessions.end();) {
        if (!isValidSession(it->first)) {
            it = sessions.erase(it); // Remove expired session
        }
        else {
            ++it;
        }
    }
}

