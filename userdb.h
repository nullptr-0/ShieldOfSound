#include <sqlite3.h>
#include <string>
#include <vector>
#include "user.h"

class UserDatabase {
public:
    UserDatabase(const std::string& dbName);
    ~UserDatabase();
    void createTable();
    std::string getCurrentTime();
    size_t getUserCount();
    size_t getAdminCount();
    bool registerUser(const std::string& username, const std::string& password);
    bool checkCredential(const std::string& username, const std::string& password);
    bool login(const std::string& username, const std::string& password);
    bool updateLastLoginTime(const std::string& username);
    bool updatePassword(const std::string& username, const std::string& newPassword);
    bool deleteUser(const std::string& username);
    bool isAdmin(const std::string& username);
    bool updateUserRole(const std::string& username, bool isAdmin);
    std::vector<User> getUsersPaginated(size_t page, size_t pageSize, const std::string& sortField, const std::string& sortOrder);
private:
    sqlite3* db;
};
