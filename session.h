#include <unordered_map>
#include <string>
#include <ctime>
#include <chrono>

struct Session {
    std::string username;
    std::chrono::steady_clock::time_point lastActivity;
    uint32_t timeoutSeconds = 1800;
};

class SessionManager {
public:
    std::string createSession(const std::string& username, uint32_t timeoutSeconds = 1800);
    bool isValidSession(const std::string& sessionId);
    void updateSession(const std::string& sessionId);
    void destroyUserSessions(const std::string& username);
    void destroySession(const std::string& sessionId);
    std::string getUsername(const std::string& sessionId);
    void clearExpiredSessions();

private:
    std::unordered_map<std::string, Session> sessions; // session_id -> session_info
    std::unordered_map<std::string, std::vector<std::string>> userSessions; // username -> session_id
    std::string generateSessionId();
};
