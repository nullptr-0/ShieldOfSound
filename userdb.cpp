#include <iostream>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <Argon2/argon2.h>
#include <base64.hpp>
#include "userdb.h"

std::string uint32ToString(uint32_t value, size_t length) {
    std::ostringstream oss;
    oss << value;
    std::string result = oss.str();

    if (result.length() > length) {
        return result.substr(0, length); 
    }
    return result.insert(0, length - result.length(), '0');
}

std::string uint8ArrayToHexString(const uint8_t* array, size_t length) {
    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(array[i]);
    }
    return oss.str();
}

std::string hashPassword(const std::string& username, const std::string& password) {
    unsigned char out[ARGON2_OUT_LEN_DEF];
    uint32_t m_cost = 1 << ARGON2_LOG_M_COST_DEF;
    uint32_t t_cost = ARGON2_T_COST_DEF;
    uint32_t lanes = ARGON2_LANES_DEF;
    uint32_t threads = ARGON2_THREADS_DEF;
    char* pwd = (char*)password.c_str();
    std::string saltStr = uint32ToString(std::hash<std::string>()(username), ARGON2_SALT_LEN_DEF);
    uint8_t* salt = (uint8_t*)saltStr.c_str();
    const char* type = "id";

    uint32_t out_length = ARGON2_OUT_LEN_DEF;
    uint32_t salt_length = ARGON2_SALT_LEN_DEF;
    uint8_t* secret = NULL;
    uint32_t secret_length = 0;
    uint8_t* ad = NULL;
    uint32_t ad_length = 0;
    bool clear_memory = false;
    bool clear_secret = false;
    bool clear_password = false;
    bool print_internals = false;

    size_t pwd_length = strlen(pwd);

    Argon2_Context context(out, out_length, (uint8_t*)pwd, pwd_length, salt, salt_length,
        secret, secret_length, ad, ad_length, t_cost, m_cost, lanes, threads,
        NULL, NULL,
        clear_password, clear_secret, clear_memory, print_internals);

    int result = Argon2id(&context);
    if (result != ARGON2_OK) {
        std::cerr << ErrorMessage(result) << "\n";
    }

    return uint8ArrayToHexString(out, context.outlen);
}

UserDatabase::UserDatabase(const std::string& dbName) {
    sqlite3_open(dbName.c_str(), &db);
}

UserDatabase::~UserDatabase() {
    sqlite3_close(db);
}

void UserDatabase::createTable() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            is_admin BOOLEAN DEFAULT 0,
            registration_time TEXT,
            last_login_time TEXT
        );
    )";
    sqlite3_exec(db, sql, nullptr, 0, nullptr);
}

std::string UserDatabase::getCurrentTime() {
    std::time_t now = std::time(nullptr);
    std::tm* tm_now = std::localtime(&now);
    std::ostringstream oss;
    oss << std::put_time(tm_now, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

size_t UserDatabase::getUserCount() {
    size_t rowCount = 0;
    const char* sql = "SELECT COUNT(*) FROM users;";

    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        rowCount = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return rowCount;
}

size_t UserDatabase::getAdminCount() {
    size_t rowCount = 0;
    const char* sql = "SELECT COUNT(*) FROM users WHERE is_admin = 1;";

    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        rowCount = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return rowCount;
}

bool UserDatabase::registerUser(const std::string& username, const std::string& password) {
    std::string encodedUsername = encodeStrToBase64(username);
    std::string hashedPassword = hashPassword(encodedUsername, password);
    std::string currentTime = getCurrentTime();
    const char* sql = "INSERT INTO users (username, password, is_admin, registration_time, last_login_time) VALUES (?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, encodedUsername.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hashedPassword.c_str(), -1, SQLITE_STATIC);

    // Check if first user to register
    bool isFirstUser = (getUserCount() == 0);
    sqlite3_bind_int(stmt, 3, isFirstUser ? 1 : 0);
    sqlite3_bind_text(stmt, 4, currentTime.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, currentTime.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool UserDatabase::checkCredential(const std::string& username, const std::string& password)
{
    std::string encodedUsername = encodeStrToBase64(username);
    const char* sql = "SELECT password FROM users WHERE username = ?;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, encodedUsername.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* hashedPassword = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        bool valid = hashPassword(encodedUsername, password) == hashedPassword;
        sqlite3_finalize(stmt);

        return valid;
    }

    sqlite3_finalize(stmt);
    return false;
}

bool UserDatabase::login(const std::string& username, const std::string& password) {
    if (checkCredential(username, password)) {
        return updateLastLoginTime(username); // Update last login time
    }
    return false;
}

bool UserDatabase::updateLastLoginTime(const std::string& username) {
    std::string encodedUsername = encodeStrToBase64(username);
    std::string currentTime = getCurrentTime();
    const char* sql = "UPDATE users SET last_login_time = ? WHERE username = ?;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, currentTime.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, encodedUsername.c_str(), -1, SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool UserDatabase::updatePassword(const std::string& username, const std::string& newPassword) {
    std::string encodedUsername = encodeStrToBase64(username);
    std::string newHashedPassword = hashPassword(encodedUsername, newPassword);
    const char* sql = "UPDATE users SET password = ? WHERE username = ?;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, newPassword.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, encodedUsername.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool UserDatabase::deleteUser(const std::string& username) {
    std::string encodedUsername = encodeStrToBase64(username);
    const char* sql = "DELETE FROM users WHERE username = ?;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, encodedUsername.c_str(), -1, SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool UserDatabase::isAdmin(const std::string& username) {
    std::string encodedUsername = encodeStrToBase64(username);
    const char* sql = "SELECT is_admin FROM users WHERE username = ?;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, encodedUsername.c_str(), -1, SQLITE_STATIC);

    bool isAdmin = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        isAdmin = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return isAdmin;
}

bool UserDatabase::updateUserRole(const std::string& username, bool isAdmin) {
    std::string encodedUsername = encodeStrToBase64(username);
    const char* sql = "UPDATE users SET is_admin = ? WHERE username = ?;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, isAdmin ? 1 : 0);
    sqlite3_bind_text(stmt, 2, encodedUsername.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

std::vector<User> UserDatabase::getUsersPaginated(size_t page, size_t pageSize, const std::string& sortField, const std::string& sortOrder) {
    std::vector<User> users;

    std::string validSortFields[] = { "username", "is_admin", "registration_time", "last_login_time" };
    std::string sortQuery = "ORDER BY " + (std::find(std::begin(validSortFields), std::end(validSortFields), sortField) != std::end(validSortFields) ? sortField : "username") + " " + (sortOrder == "desc" ? "DESC" : "ASC");

    std::string sqlQueryStr = "SELECT username, is_admin, registration_time, last_login_time FROM users " + sortQuery + " LIMIT ? OFFSET ?;";
    const char* sql = sqlQueryStr.c_str();
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    size_t offset = (page - 1) * pageSize;
    sqlite3_bind_int(stmt, 1, pageSize);
    sqlite3_bind_int(stmt, 2, offset);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        User user;
        user.username = decodeStrFromBase64(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
        user.isAdmin = sqlite3_column_int(stmt, 1);
        user.registrationTime = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        user.lastLoginTime = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        users.push_back(user);
    }

    sqlite3_finalize(stmt);
    return users;
}
