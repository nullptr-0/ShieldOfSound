#include <sqlite3.h>
#include <string>
#include <vector>
#include "file.h"

class FileDatabase {
public:
    FileDatabase(const std::string& dbName);
    ~FileDatabase();
    void createTable();
    std::string getCurrentTime();
    size_t getCreatorFileCount(const std::string& creator);
    size_t getFileCount();
    bool addFile(const std::string& filename, const std::string& title, const std::string& description, const std::string& creator);
    bool deleteFile(const std::string& filename);
    std::vector<File> getCreatorFilesPaginated(const std::string& creator, size_t page, size_t pageSize, const std::string& sortField, const std::string& sortOrder);
    std::vector<File> getFilesPaginated(size_t page, size_t pageSize, const std::string& sortField, const std::string& sortOrder);
    bool isFileCreator(const std::string& filename, const std::string& creator);
    File getFileDetail(const std::string& filename);
    std::vector<File> searchFiles(const std::string& filename, const std::string& title, const std::string& creator, const std::string& addedTime);
private:
    sqlite3* db;
};
