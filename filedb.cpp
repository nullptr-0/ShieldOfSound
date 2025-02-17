#include <iostream>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <algorithm>
#include <base64.hpp>
#include "filedb.h"

FileDatabase::FileDatabase(const std::string& dbName) {
    sqlite3_open(dbName.c_str(), &db);
}

FileDatabase::~FileDatabase() {
    sqlite3_close(db);
}

void FileDatabase::createTable() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT UNIQUE,
            title TEXT,
            description TEXT,
            creator TEXT,
            added_time TEXT
        );
    )";
    sqlite3_exec(db, sql, nullptr, 0, nullptr);
}

std::string FileDatabase::getCurrentTime() {
    std::time_t now = std::time(nullptr);
    std::tm* tm_now = std::localtime(&now);
    std::ostringstream oss;
    oss << std::put_time(tm_now, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

size_t FileDatabase::getCreatorFileCount(const std::string& creator) {
    size_t rowCount = 0;
    const char* sql = "SELECT COUNT(*) FROM files WHERE creator = ?;";

    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, creator.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        rowCount = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return rowCount;
}

size_t FileDatabase::getFileCount() {
    size_t rowCount = 0;
    const char* sql = "SELECT COUNT(*) FROM files;";

    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        rowCount = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return rowCount;
}

bool FileDatabase::addFile(const std::string& filename, const std::string& title, const std::string& description, const std::string& creator) {
    std::string currentTime = getCurrentTime();
    const char* sql = "INSERT INTO files (filename, title, description, creator, added_time) VALUES (?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, filename.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, title.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, description.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, creator.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, currentTime.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool FileDatabase::deleteFile(const std::string& filename) {
    const char* sql = "DELETE FROM files WHERE filename = ?;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, filename.c_str(), -1, SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

std::vector<File> FileDatabase::getCreatorFilesPaginated(const std::string& creator, size_t page, size_t pageSize, const std::string& sortField, const std::string& sortOrder) {
    std::vector<File> files;

    std::string validSortFields[] = { "filename", "title", "added_time" };
    std::string sortQuery = "ORDER BY " + (std::find(std::begin(validSortFields), std::end(validSortFields), sortField) != std::end(validSortFields) ? sortField : "filename") + " " + (sortOrder == "desc" ? "DESC" : "ASC");

    std::string sqlQueryStr = "SELECT filename, title, description, added_time FROM files WHERE creator = ? " + sortQuery + " LIMIT ? OFFSET ?;";
    const char* sql = sqlQueryStr.c_str();
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    sqlite3_bind_text(stmt, 1, creator.c_str(), -1, SQLITE_STATIC);

    size_t offset = (page - 1) * pageSize;
    sqlite3_bind_int(stmt, 2, pageSize);
    sqlite3_bind_int(stmt, 3, offset);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        File file;
        file.filename = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        file.title = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        file.description = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        file.addedTime = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        files.push_back(file);
    }

    sqlite3_finalize(stmt);
    return files;
}

std::vector<File> FileDatabase::getFilesPaginated(size_t page, size_t pageSize, const std::string& sortField, const std::string& sortOrder) {
    std::vector<File> files;

    std::string validSortFields[] = { "filename", "title", "creator", "added_time" };
    std::string sortQuery = "ORDER BY " + (std::find(std::begin(validSortFields), std::end(validSortFields), sortField) != std::end(validSortFields) ? sortField : "filename") + " " + (sortOrder == "desc" ? "DESC" : "ASC");

    std::string sqlQueryStr = "SELECT filename, title, description, creator, added_time FROM files " + sortQuery + " LIMIT ? OFFSET ?;";
    const char* sql = sqlQueryStr.c_str();
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    size_t offset = (page - 1) * pageSize;
    sqlite3_bind_int(stmt, 1, pageSize);
    sqlite3_bind_int(stmt, 2, offset);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        File file;
        file.filename = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        file.title = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        file.description = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        file.creator = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        file.addedTime = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        files.push_back(file);
    }

    sqlite3_finalize(stmt);
    return files;
}

bool FileDatabase::isFileCreator(const std::string& filename, const std::string& creator) {
    size_t rowCount = 0;
    const char* sql = "SELECT COUNT(*) FROM files WHERE filename = ? AND creator = ?;";

    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, filename.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, creator.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        rowCount = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return rowCount;
}

File FileDatabase::getFileDetail(const std::string& filename) {
    File file;

    std::string sqlQueryStr = "SELECT filename, title, description, creator, added_time FROM files WHERE filename = ?;";
    const char* sql = sqlQueryStr.c_str();
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    sqlite3_bind_text(stmt, 1, filename.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        file.filename = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        file.title = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        file.description = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        file.creator = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        file.addedTime = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
    }

    sqlite3_finalize(stmt);
    return file;
}

std::vector<File> FileDatabase::searchFiles(const std::string& filename, const std::string& title, const std::string& creator, const std::string& addedTime) {
    std::vector<File> results;
    std::string sql = "SELECT filename, title, description, creator, added_time FROM files WHERE 1=1";
    if (!filename.empty()) sql += " AND filename LIKE ?";
    if (!title.empty()) sql += " AND title LIKE ?";
    if (!creator.empty()) sql += " AND creator LIKE ?";
    if (!addedTime.empty()) sql += " AND added_time LIKE ?";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return results;
    }

    auto filenameParam = "%" + filename + "%";
    auto titleParam = "%" + title + "%";
    auto addedTimeParam = addedTime + "%";
    int param_index = 1;
    if (!filename.empty()) {
        sqlite3_bind_text(stmt, param_index++, filenameParam.c_str(), -1, SQLITE_STATIC);
    }
    if (!title.empty()) {
        sqlite3_bind_text(stmt, param_index++, titleParam.c_str(), -1, SQLITE_STATIC);
    }
    if (!creator.empty()) {
        sqlite3_bind_text(stmt, param_index++, creator.c_str(), -1, SQLITE_STATIC);
    }
    if (!addedTime.empty()) {
        sqlite3_bind_text(stmt, param_index++, addedTimeParam.c_str(), -1, SQLITE_STATIC);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        File file;
        file.filename = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        file.title = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        file.description = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        file.creator = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        file.addedTime = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        results.push_back(file);
    }

    sqlite3_finalize(stmt);
    return results;
}
