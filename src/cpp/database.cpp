#include "../h/database.h"
#include <iostream>

Database::Database(const std::string& path) : db_path(path), db(nullptr) {
    int rc = sqlite3_open(db_path.c_str(), &db);
    if (rc != SQLITE_OK) {
        std::cerr << "Database opening error: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        db = nullptr;
    }
}

Database::~Database() {
    if (db) {
        sqlite3_close(db);
    }
}

bool Database::initialize() {
    if (!db) return false;

    const char* create_users_sql = 
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT NOT NULL UNIQUE,"
        "password_hash TEXT NOT NULL,"
        "totp_secret TEXT NOT NULL);";

    const char* create_passwords_sql = 
        "CREATE TABLE IF NOT EXISTS passwords ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "user_id INTEGER NOT NULL,"
        "description TEXT NOT NULL,"
        "login TEXT NOT NULL,"
        "password BLOB NOT NULL,"
        "FOREIGN KEY (user_id) REFERENCES users (id));";

    char* err_msg = nullptr;
    int rc = sqlite3_exec(db, create_users_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "The error of creating a table users: " << err_msg << std::endl;
        sqlite3_free(err_msg);
        return false;
    }

    rc = sqlite3_exec(db, create_passwords_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "The error of creating a table passwords: " << err_msg << std::endl;
        sqlite3_free(err_msg);
        return false;
    }

    return true;
}

bool Database::registerUser(const std::string& username, const std::string& password_hash, const std::string& totp_secret) {
    if (!db) return false;

    const char* sql = "INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?);";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Request error: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, totp_secret.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    bool success = (rc == SQLITE_DONE);
    if (!success) {
        std::cerr << "Registration error: " << sqlite3_errmsg(db) << std::endl;
    }

    sqlite3_finalize(stmt);
    return success;
}

bool Database::authenticateUser(const std::string& username, const std::string& password_hash, int& user_id, std::string& totp_secret) {
    if (!db) return false;

    const char* sql = "SELECT id, totp_secret FROM users WHERE username = ? AND password_hash = ?;";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Request error: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        user_id = sqlite3_column_int(stmt, 0);
        totp_secret = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        sqlite3_finalize(stmt);
        return true;
    }

    sqlite3_finalize(stmt);
    return false;
}

bool Database::addPassword(int user_id, const PasswordEntry& entry) {
    if (!db) return false;

    const char* sql = "INSERT INTO passwords (user_id, description, login, password) VALUES (?, ?, ?, ?);";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Request error: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, entry.description.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, entry.login.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, entry.password.data(), entry.password.size(), SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    bool success = (rc == SQLITE_DONE);
    if (!success) {
        std::cerr << "An error of adding a record: " << sqlite3_errmsg(db) << std::endl;
    }

    sqlite3_finalize(stmt);
    return success;
}

bool Database::removePassword(int user_id, const std::string& description) {
    if (!db) return false;

    const char* sql = "DELETE FROM passwords WHERE user_id = ? AND description = ?;";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Request error: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, description.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    bool success = (rc == SQLITE_DONE && sqlite3_changes(db) > 0);
    if (!success && sqlite3_changes(db) == 0) {
        std::cerr << "The record is not found!" << std::endl;
    }

    sqlite3_finalize(stmt);
    return success;
}

bool Database::getPasswords(int user_id, std::vector<PasswordEntry>& entries) {
    if (!db) return false;

    entries.clear();
    const char* sql = "SELECT description, login, password FROM passwords WHERE user_id = ?;";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Request error: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_int(stmt, 1, user_id);

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        PasswordEntry entry;
        entry.description = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        entry.login = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const void* blob = sqlite3_column_blob(stmt, 2);
        int blob_size = sqlite3_column_bytes(stmt, 2);
        entry.password = std::string(static_cast<const char*>(blob), blob_size);
        entries.push_back(entry);
    }

    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE || !entries.empty();
}