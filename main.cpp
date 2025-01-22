#include "userdb.h"
#include "filedb.h"
#include "session.h"
#include "user.h"
#include "file.h"
#include "netutil.hpp"
#include <regex>
#include <filesystem>
#include <httplib.h>
#include <json.hpp>
#include "rsacrypto.hpp"

using json = nlohmann::json;

bool isValidPassword(const std::string& password) {
    if (password.length() < 8) return false;
    std::regex hasLower("[a-z]");
    std::regex hasUpper("[A-Z]");
    std::regex hasDigit("[0-9]");
    std::regex hasSpecial("[^a-zA-Z0-9]");

    int complexity = 0;
    complexity += std::regex_search(password, hasLower) ? 1 : 0;
    complexity += std::regex_search(password, hasUpper) ? 1 : 0;
    complexity += std::regex_search(password, hasDigit) ? 1 : 0;
    complexity += std::regex_search(password, hasSpecial) ? 1 : 0;

    return complexity >= 2; // At least two types of characters
}

bool isValidFilename(const std::string& filename) {
    // Maximum length for many OS filesystems is 255 characters
    if (filename.empty() || filename.length() > 255) {
        return false;
    }

    // Forbidden characters
    const std::string forbiddenChars =
#ifdef _WIN32
        "<>:\"/\\|?*"
#else
        "/"
#endif
        ;
    for (char ch : filename) {
        if (forbiddenChars.find(ch) != std::string::npos) {
            return false;
        }
    }

    return true;
}

std::string generateUserListJson(const std::vector<User>& users, size_t totalUsers) {
    json userList = json::array();
    for (const auto& user : users) {
        userList.push_back(json{ {"username", user.username}, {"isAdmin", (user.isAdmin ? "Yes" : "No")}, {"registrationTime", user.registrationTime}, {"lastLoginTime", user.lastLoginTime} });
    }
    userList = {
        {"totalUsers", totalUsers},
        {"userList", userList}
    };
    return userList.dump();
}

std::string generateFileDetailJson(const File& file) {
    return json{ {"filename", file.filename}, {"title", file.title}, {"description", file.description}, {"creator", file.creator}, {"addedTime", file.addedTime} }.dump();
}

std::string generateFileListJson(const std::vector<File>& files, size_t totalFiles) {
    json fileList = json::array();
    for (const auto& file : files) {
        fileList.push_back(json{ {"filename", file.filename}, {"title", file.title}, {"description", file.description}, {"creator", file.creator}, {"addedTime", file.addedTime} });
    }
    fileList = {
        {"totalFiles", totalFiles},
        {"fileList", fileList}
    };
    return fileList.dump();
}

std::string generateAppListJson(bool isAdmin) {
    json appList = {
        {
            {"name", "Resource Upload"},
            {"endpoint", "/file"}
        },
        {
            {"name", "Manage Profile"},
            {"endpoint", "/profile"}
        },
        {
            {"name", "Logout"},
            {"endpoint", "/logout"}
        },
    };
    json adminAppList = {
        {
            {"name", "User Management"},
            {"endpoint", "/admin/users"}
        },
        {
            {"name", "File Management"},
            {"endpoint", "/admin/files"}
        },
    };
    if (isAdmin) {
        for (auto& adminApp : adminAppList) {
            appList.push_back(adminApp);
        }
    }
    return appList.dump();
}

int main() {
    auto [pvk, pbk] = generate_key_pair(2048);

    httplib::Server svr;

    UserDatabase userDb("sos.db");
    userDb.createTable();

    FileDatabase fileDb("sos.db");
    fileDb.createTable();

    std::string uploadDir = "upload";
    if (!std::filesystem::exists(uploadDir)) {
        if (!std::filesystem::create_directory(uploadDir)) {
            std::cerr << "Create upload directory failed" << std::endl;
            return 1;
        }
    }

    // Session store
    SessionManager sessionManager;

    auto saveFile = [](const std::string& filename, const std::string& content) {
        FILE* file = fopen(filename.c_str(), "wb");
        if (file) {
            fwrite(content.data(), 1, content.size(), file);
            fclose(file);
            return true;
        }
        else {
            std::cerr << "Write " << filename << " failed\n";
            return false;
        }
        };

    auto deleteFile = [](const std::string& filename) {
        try {
            if (std::filesystem::remove(filename)) {
                return true;
            }
            std::cerr << "File " << filename << " not found\n";
        }
        catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "Error: " << e.what() << '\n';
        }
        return false;
        };

    auto getFile = [](const std::string& contentPath, httplib::Response& res) {
        FILE* file = fopen(contentPath.c_str(), "rb");
        if (file) {
            fseek(file, 0, SEEK_END);
            size_t fileSize = ftell(file);
            fseek(file, 0, SEEK_SET);

            char* buffer = new char[fileSize];
            fread(buffer, 1, fileSize, file);

            std::unordered_map<std::string, std::string> mimeTypes = {
                {"html", "text/html"},
                {"js", "text/javascript"}
            };
            res.set_content(buffer, fileSize, mimeTypes[contentPath.substr(contentPath.find_last_of('.') + 1)]);

            delete[] buffer;
            fclose(file);
            res.status = 200;
        }
        else {
            res.status = 404;
        }
        };

    svr.Get("/public_key", [&pbk](const httplib::Request&, httplib::Response& res) {
        res.status = 200;
        res.set_content(pbk, "text/plain");
        });

    svr.Get("/", [&sessionManager](const httplib::Request& req, httplib::Response& res) {
        if (!sessionManager.isValidSession(parseCookies(req.get_header_value("Cookie"))["session_id"])) {
            res.set_redirect("/login");
        }
        else {
            res.set_redirect("/dashboard");
        }
        });

    svr.Get("/login", [&getFile](const httplib::Request&, httplib::Response& res) {
        getFile("ui/login.html", res);
        });

    svr.Post("/login", [&pvk, &userDb, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        std::string username = RsaDecrypt(req.get_file_value("username").content, pvk);
        std::string password = RsaDecrypt(req.get_file_value("password").content, pvk);
        if (userDb.login(username, password)) {
            auto sessionId = sessionManager.createSession(username);
            res.set_redirect("/dashboard");
            res.set_header("Set-Cookie", "session_id=" + sessionId + "; HttpOnly; SameSite=Strict");
        }
        else {
            res.status = 403;
            res.set_content("Invalid credentials", "text/plain");
        }
        sessionManager.clearExpiredSessions();
        });

    svr.Get("/register", [&getFile](const httplib::Request&, httplib::Response& res) {
        getFile("ui/register.html", res);
        });

    svr.Post("/register", [&pvk, &userDb](const httplib::Request& req, httplib::Response& res) {
        std::string username = RsaDecrypt(req.get_file_value("username").content, pvk);
        std::string password = RsaDecrypt(req.get_file_value("password").content, pvk);
        if (isValidPassword(password)) {
            if (userDb.registerUser(username, password)) {
                res.set_redirect("/login");
            }
            else {
                res.status = 400;
                res.set_content("Registration failed", "text/plain");
            }
        }
        else {
            res.status = 400;
            res.set_content("Invalid password", "text/plain");
        }
        });

    svr.Get("/dashboard", [&getFile, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (!sessionManager.isValidSession(sessionId)) {
            res.set_redirect("/login");
        }
        else {
            sessionManager.updateSession(sessionId);
            getFile("ui/dashboard.html", res);
        }
        });

    svr.Get("/apps", [&userDb, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (!sessionManager.isValidSession(sessionId)) {
            res.set_redirect("/login");
        }
        else {
            sessionManager.updateSession(sessionId);
            std::string responseJson = generateAppListJson(userDb.isAdmin(sessionManager.getUsername(sessionId)));
            res.status = 200;
            res.set_content(responseJson, "application/json");
        }
        });

    svr.Get("/profile", [&getFile, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (!sessionManager.isValidSession(sessionId)) {
            res.set_redirect("/login");
        }
        else {
            sessionManager.updateSession(sessionId);
            getFile("ui/profile.html", res);
        }
        });

    svr.Post("/update_profile", [&pvk, &userDb, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (!sessionManager.isValidSession(sessionId)) {
            res.set_redirect("/login");
        }
        else {
            sessionManager.updateSession(sessionId);
            auto username = sessionManager.getUsername(sessionId);
            std::string newPassword = RsaDecrypt(req.get_file_value("new_password").content, pvk);
            if (!newPassword.empty()) {
                if (isValidPassword(newPassword)) {
                    if (userDb.updatePassword(username, newPassword)) {
                        res.status = 200;
                        res.set_content("Password updated successfully", "text/plain");
                    }
                    else {
                        res.status = 400;
                        res.set_content("Password update failed", "text/plain");
                    }
                }
                else {
                    res.status = 400;
                    res.set_content("Invalid password", "text/plain");
                }
            }
            else {
                res.status = 200;
                res.set_content("Nothing to do", "text/plain");
            }
        }
        });

    svr.Post("/delete_account", [&pvk, &userDb, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (sessionManager.isValidSession(sessionId)) {
            std::string username = RsaDecrypt(req.get_file_value("confirm_username").content, pvk);
            std::string password = RsaDecrypt(req.get_file_value("confirm_password").content, pvk);
            if (username == sessionManager.getUsername(sessionId)) {
                if (userDb.checkCredential(username, password)) {
                    userDb.deleteUser(username);
                    sessionManager.destroyUserSessions(username);
                    res.set_header("Set-Cookie", "session_id=; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict");
                    res.set_redirect("/login");
                }
                else {
                    res.status = 403;
                    res.set_content("Incorrect credentials for confirmation", "text/plain");
                }
            }
            else {
                res.status = 403;
                res.set_content("Incorrect credentials for confirmation", "text/plain");
            }
        }
        else {
            res.set_redirect("/login");
        }
        });

    svr.Get("/logout", [&sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (sessionManager.isValidSession(sessionId)) {
            sessionManager.destroySession(sessionId);
            res.set_header("Set-Cookie", "session_id=; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict");
        }
        res.set_redirect("/login");
        });

    // Admin route
    svr.Get("/admin/users", [&getFile, &userDb, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (!sessionManager.isValidSession(sessionId)) {
            res.set_redirect("/login");
        }
        else {
            if (!userDb.isAdmin(sessionManager.getUsername(sessionId))) {
                res.status = 403;
                res.set_content("Access denied", "text/plain");
            }
            else {
                sessionManager.updateSession(sessionId);
                getFile("ui/admin/users.html", res);
            }
        }
        });

    svr.Get("/admin/list_users", [&userDb, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (!sessionManager.isValidSession(sessionId)) {
            res.set_redirect("/login");
        }
        else {
            if (!userDb.isAdmin(sessionManager.getUsername(sessionId))) {
                res.status = 403;
                res.set_content("Access denied", "text/plain");
            }
            else {
                sessionManager.updateSession(sessionId);
                size_t page = std::stoi(req.get_param_value("page"));
                size_t pageSize = std::stoi(req.get_param_value("page_size"));
                std::string sortField = req.get_param_value("sort_field");
                std::string sortOrder = req.get_param_value("sort_order");

                std::vector<User> users = userDb.getUsersPaginated(page, pageSize, sortField, sortOrder);
                std::string responseJson = generateUserListJson(users, userDb.getUserCount());
                
                res.status = 200;
                res.set_content(responseJson, "application/json");
            }
        }
        });

    svr.Post("/admin/update_user", [&pvk, &userDb, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (!sessionManager.isValidSession(sessionId)) {
            res.set_redirect("/login");
        }
        else {
            if (!userDb.isAdmin(sessionManager.getUsername(sessionId))) {
                res.status = 403;
                res.set_content("Access denied", "text/plain");
            }
            else {
                sessionManager.updateSession(sessionId);
                auto username = RsaDecrypt(req.get_file_value("username").content, pvk);
                bool isAdmin = RsaDecrypt(req.get_file_value("is_admin").content, pvk) == "Yes";
                if (userDb.getAdminCount() == 1 && !isAdmin) {
                    res.status = 400;
                    res.set_content("Invalid operation", "text/plain");
                }
                else if (!userDb.updateUserRole(username, isAdmin)) {
                    res.status = 400;
                    res.set_content("User update failed", "text/plain");
                }
                else {
                    res.status = 200;
                    res.set_content("User updated", "text/plain");
                }
            }
        }
        });

    svr.Post("/admin/delete_user", [&pvk, &userDb, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (!sessionManager.isValidSession(sessionId)) {
            res.set_redirect("/login");
        }
        else {
            if (!userDb.isAdmin(sessionManager.getUsername(sessionId))) {
                res.status = 403;
                res.set_content("Access denied", "text/plain");
            }
            else {
                sessionManager.updateSession(sessionId);
                auto username = RsaDecrypt(req.get_file_value("username").content, pvk);
                if (username == sessionManager.getUsername(sessionId)) {
                    res.status = 400;
                    res.set_content("Invalid operation", "text/plain");
                }
                else {
                    userDb.deleteUser(username);

                    res.status = 200;
                    res.set_content("User deleted", "text/plain");
                }
            }
        }
        });

    svr.Get("/file", [&getFile, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (!sessionManager.isValidSession(sessionId)) {
            res.set_redirect("/login");
        }
        else {
            sessionManager.updateSession(sessionId);
            getFile("ui/file.html", res);
        }
        });

    svr.Post("/file/upload", [&saveFile, &uploadDir, &fileDb, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (!sessionManager.isValidSession(sessionId)) {
            res.set_redirect("/login");
        }
        else {
            sessionManager.updateSession(sessionId);
            auto username = sessionManager.getUsername(sessionId);
            auto filename = req.get_file_value("file").filename;
            if (isValidFilename(filename)) {
                if (fileDb.addFile(filename, req.get_file_value("title").content, req.get_file_value("description").content, username)) {
                    if (saveFile(uploadDir + "/" + filename, req.get_file_value("file").content)) {
                        res.status = 200;
                        res.set_content("File uploaded successfully", "text/plain");
                    }
                    else {
                        fileDb.deleteFile(filename);
                        res.status = 400;
                        res.set_content("File upload failed", "text/plain");
                    }
                }
                else {
                    res.status = 400;
                    res.set_content("File upload failed", "text/plain");
                }
            }
            else {
                res.status = 400;
                res.set_content("Invalid operation", "text/plain");
            }
        }
        });

    svr.Post("/file/delete", [&deleteFile, &uploadDir, &fileDb, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (!sessionManager.isValidSession(sessionId)) {
            res.set_redirect("/login");
        }
        else {
            sessionManager.updateSession(sessionId);
            auto username = sessionManager.getUsername(sessionId);
            auto filename = req.get_file_value("filename").content;
            if (fileDb.isFileCreator(filename, username)) {
                if (fileDb.deleteFile(filename)) {
                    if (deleteFile(uploadDir + "/" + req.get_file_value("filename").content)) {
                        res.status = 200;
                        res.set_content("File deleted successfully", "text/plain");
                    }
                    else {
                        res.status = 400;
                        res.set_content("File delete failed", "text/plain");
                    }
                }
                else {
                    res.status = 400;
                    res.set_content("File delete failed", "text/plain");
                }
            }
            else {
                res.status = 400;
                res.set_content("Invalid operation", "text/plain");
            }
        }
        });

    svr.Get("/file/list_files", [&fileDb, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (!sessionManager.isValidSession(sessionId)) {
            res.set_redirect("/login");
        }
        else {
            sessionManager.updateSession(sessionId);
            auto username = sessionManager.getUsername(sessionId);
            size_t page = std::stoi(req.get_param_value("page"));
            size_t pageSize = std::stoi(req.get_param_value("page_size"));
            std::string sortField = req.get_param_value("sort_field");
            std::string sortOrder = req.get_param_value("sort_order");

            std::vector<File> files = fileDb.getCreatorFilesPaginated(username, page, pageSize, sortField, sortOrder);
            std::string responseJson = generateFileListJson(files, fileDb.getCreatorFileCount(username));

            res.status = 200;
            res.set_content(responseJson, "application/json");
        }
        });

    svr.Get("/file/detail", [&fileDb, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (!sessionManager.isValidSession(sessionId)) {
            res.set_redirect("/login");
        }
        else {
            sessionManager.updateSession(sessionId);
            auto username = sessionManager.getUsername(sessionId);
            auto filename = req.get_param_value("filename");
            if (fileDb.isFileCreator(filename, username)) {
                File file = fileDb.getFileDetail(filename);
                if (!file.filename.empty()) {
                    std::string responseJson = generateFileDetailJson(file);

                    res.status = 200;
                    res.set_content(responseJson, "application/json");
                }
                else {
                    res.status = 400;
                    res.set_content("File detail fetch failed", "text/plain");
                }
            }
            else {
                res.status = 400;
                res.set_content("Invalid operation", "text/plain");
            }
        }
        });

    svr.Get("/file/search", [&fileDb, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (!sessionManager.isValidSession(sessionId)) {
            res.set_redirect("/login");
        }
        else {
            sessionManager.updateSession(sessionId);
            auto username = sessionManager.getUsername(sessionId);
            auto filename = req.has_param("filename") ? req.get_param_value("filename") : "";
            auto title = req.has_param("title") ? req.get_param_value("title") : "";
            auto added_time = req.has_param("added_time") ? req.get_param_value("added_time") : "";
            std::vector<File> files = fileDb.searchFiles(filename, title, username, added_time);
            std::string responseJson = generateFileListJson(files, files.size());

            res.status = 200;
            res.set_content(responseJson, "application/json");
        }
        });

    // Admin route
    svr.Get("/admin/files", [&getFile, &userDb, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (!sessionManager.isValidSession(sessionId)) {
            res.set_redirect("/login");
        }
        else {
            if (!userDb.isAdmin(sessionManager.getUsername(sessionId))) {
                res.status = 403;
                res.set_content("Access denied", "text/plain");
            }
            else {
                sessionManager.updateSession(sessionId);
                getFile("ui/admin/files.html", res);
            }
        }
        });

    svr.Get("/admin/list_files", [&userDb, &fileDb, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (!sessionManager.isValidSession(sessionId)) {
            res.set_redirect("/login");
        }
        else {
            if (!userDb.isAdmin(sessionManager.getUsername(sessionId))) {
                res.status = 403;
                res.set_content("Access denied", "text/plain");
            }
            else {
                sessionManager.updateSession(sessionId);
                size_t page = std::stoi(req.get_param_value("page"));
                size_t pageSize = std::stoi(req.get_param_value("page_size"));
                std::string sortField = req.get_param_value("sort_field");
                std::string sortOrder = req.get_param_value("sort_order");

                std::vector<File> files = fileDb.getFilesPaginated(page, pageSize, sortField, sortOrder);
                std::string responseJson = generateFileListJson(files, fileDb.getFileCount());

                res.status = 200;
                res.set_content(responseJson, "application/json");
            }
        }
        });

    svr.Post("/admin/delete_file", [&pvk, &userDb, &fileDb, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (!sessionManager.isValidSession(sessionId)) {
            res.set_redirect("/login");
        }
        else {
            if (!userDb.isAdmin(sessionManager.getUsername(sessionId))) {
                res.status = 403;
                res.set_content("Access denied", "text/plain");
            }
            else {
                sessionManager.updateSession(sessionId);
                auto filename = RsaDecrypt(req.get_file_value("filename").content, pvk);
                fileDb.deleteFile(filename);

                res.status = 200;
                res.set_content("File deleted", "text/plain");
            }
        }
        });

    svr.Get("/admin/download_file", [&getFile, &uploadDir, &userDb, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (!sessionManager.isValidSession(sessionId)) {
            res.set_redirect("/login");
        }
        else {
            if (!userDb.isAdmin(sessionManager.getUsername(sessionId))) {
                res.status = 403;
                res.set_content("Access denied", "text/plain");
            }
            else {
                sessionManager.updateSession(sessionId);
                auto filename = req.has_param("filename") ? req.get_param_value("filename") : "";
                if (filename.empty()) {
                    res.status = 400;
                    res.set_content("Invalid operation", "text/plain");
                }
                else {
                    getFile(uploadDir + "/" + filename, res);
                }
            }
        }
        });

    svr.Get("/admin/search_file", [&userDb, &fileDb, &sessionManager](const httplib::Request& req, httplib::Response& res) {
        auto sessionId = parseCookies(req.get_header_value("Cookie"))["session_id"];
        if (!sessionManager.isValidSession(sessionId)) {
            res.set_redirect("/login");
        }
        else {
            if (!userDb.isAdmin(sessionManager.getUsername(sessionId))) {
                res.status = 403;
                res.set_content("Access denied", "text/plain");
            }
            else {
                sessionManager.updateSession(sessionId);
                auto filename = req.has_param("filename") ? req.get_param_value("filename") : "";
                auto title = req.has_param("title") ? req.get_param_value("title") : "";
                auto username = req.has_param("creator") ? req.get_param_value("creator") : "";
                auto added_time = req.has_param("added_time") ? req.get_param_value("added_time") : "";
                std::vector<File> files = fileDb.searchFiles(filename, title, username, added_time);
                std::string responseJson = generateFileListJson(files, files.size());

                res.status = 200;
                res.set_content(responseJson, "application/json");
            }
        }
        });

    svr.listen("127.0.0.1", 4534);
}
