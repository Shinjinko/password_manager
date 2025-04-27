#ifndef DATABASE_H
#define DATABASE_H

#include <string>
#include <vector>
#include <sqlite3.h>

struct PasswordEntry {
    std::string description;
    std::string login;
    std::string password; // Зашифрованный пароль (AES-256-GCM)
};

class Database {
private:
    std::string db_path;
    sqlite3* db;

public:
    Database(const std::string& path);
    ~Database();

    // Инициализация таблиц
    bool initialize();

    // Регистрация пользователя
    bool registerUser(const std::string& username, const std::string& password_hash, const std::string& totp_secret);

    // Аутентификация пользователя
    bool authenticateUser(const std::string& username, const std::string& password_hash, int& user_id, std::string& totp_secret);

    // CRUD для паролей
    bool addPassword(int user_id, const PasswordEntry& entry);
    bool removePassword(int user_id, const std::string& description);
    bool getPasswords(int user_id, std::vector<PasswordEntry>& entries);
};

#endif // DATABASE_H