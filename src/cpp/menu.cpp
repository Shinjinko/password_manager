#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <limits>
#include "../h/pass_gen.h"
#include "../h/crypto.h"
#include "../h/exceptions.h"
#include "../h/database.h"
#include "../h/totp.h"
#include "../h/mmap_utils.h"
#include "../h/import_export.h"

void showAuthMenu() {
    std::cout << "\nМенеджер паролей CLI - Аутентификация" << std::endl;
    std::cout << "1. Войти" << std::endl;
    std::cout << "2. Зарегистрироваться" << std::endl;
    std::cout << "3. Выйти" << std::endl;
}

void showMainMenu() {
    std::cout << "\nМенеджер паролей CLI" << std::endl;
    std::cout << "1. Добавить пароль" << std::endl;
    std::cout << "2. Удалить пароль" << std::endl;
    std::cout << "3. Вывести список" << std::endl;
    std::cout << "4. Экспортировать пароли" << std::endl;
    std::cout << "5. Импортировать пароли" << std::endl;
    std::cout << "6. Выйти" << std::endl;
}

int choosePasswordMethod() {
    std::cout << "1. Ввести пароль вручную" << std::endl;
    std::cout << "2. Сгенерировать пароль" << std::endl;
    return Exceptions::getValidNumber(1, 2);
}

bool getPasswordGenerationParams(int& length, bool& useLower, bool& useUpper, bool& useDigits, bool& useSymbols) {
    length = Exceptions::getValidNumber(1, 214, "Введите длину пароля: ");

    char input;
    std::cout << "Использовать строчные буквы? (y/n): ";
    std::cin >> input;
    useLower = (input == 'y' || input == 'Y');
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    std::cout << "Использовать заглавные буквы? (y/n): ";
    std::cin >> input;
    useUpper = (input == 'y' || input == 'Y');
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    std::cout << "Использовать цифры? (y/n): ";
    std::cin >> input;
    useDigits = (input == 'y' || input == 'Y');
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    std::cout << "Использовать символы? (y/n): ";
    std::cin >> input;
    useSymbols = (input == 'y' || input == 'Y');
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    return true;
}

bool authenticate(Database& db, Crypto& crypto, int& user_id) {
    while (true) {
        showAuthMenu();
        int choice = Exceptions::getValidNumber(1, 3);
        if (choice == 3) {
            std::cout << "Выход..." << std::endl;
            return false;
        }

        std::string username, password, totp_code;
        std::cout << "Введите имя пользователя: ";
        std::getline(std::cin, username);
        std::cout << "Введите пароль: ";
        std::getline(std::cin, password);
        std::string password_hash = crypto.hashPassword(password);

        if (choice == 1) { // Вход
            std::string totp_secret;
            if (db.authenticateUser(username, password_hash, user_id, totp_secret)) {
                std::cout << "Введите TOTP-код: ";
                std::getline(std::cin, totp_code);
                if (MMAPUtils::isCodeInCache("2fa_cache.bin", user_id, totp_code)) {
                    std::cout << "TOTP-код уже использован!" << std::endl;
                    continue;
                }
                if (TOTP::verifyCode(totp_secret, totp_code)) {
                    MMAPUtils::addTOTPCacheEntry("2fa_cache.bin", user_id, totp_code);
                    std::cout << "Вход успешен!" << std::endl;
                    return true;
                } else {
                    std::cout << "Неверный TOTP-код!" << std::endl;
                }
            } else {
                std::cout << "Неверное имя пользователя или пароль!" << std::endl;
            }
        } else if (choice == 2) { // Регистрация
            std::string totp_secret = TOTP::generateSecret();
            if (db.registerUser(username, password_hash, totp_secret)) {
                std::cout << "Регистрация успешна! Ваш TOTP секрет: " << totp_secret 
                          << "\nСохраните его для настройки 2FA (например, в Google Authenticator)." << std::endl;
            } else {
                std::cout << "Ошибка регистрации: пользователь уже существует или другая ошибка." << std::endl;
            }
        }
    }
}

void addPassword(Database& db, Crypto& crypto, int user_id) {
    PasswordEntry entry;
    std::cout << "Введите описание (сайт): ";
    std::getline(std::cin, entry.description);
    std::cout << "Введите логин: ";
    std::getline(std::cin, entry.login);

    int choice = choosePasswordMethod();

    if (choice == 1) {
        std::cout << "Введите пароль: ";
        std::getline(std::cin, entry.password);
    } else if (choice == 2) {
        int length;
        bool useLower, useUpper, useDigits, useSymbols;

        if (!getPasswordGenerationParams(length, useLower, useUpper, useDigits, useSymbols)) {
            return;
        }

        entry.password = generatePassword(length, useLower, useUpper, useDigits, useSymbols);

        if (entry.password.empty()) {
            std::cout << "Не удалось сгенерировать пароль!" << std::endl;
            return;
        }
    }

    try {
        entry.password = crypto.encrypt(entry.password);
    } catch (const std::exception& e) {
        std::cout << "Ошибка шифрования: " << e.what() << std::endl;
        return;
    }

    if (db.addPassword(user_id, entry)) {
        std::cout << "Запись добавлена!" << std::endl;
    } else {
        std::cout << "Ошибка добавления записи!" << std::endl;
    }
}

void removePassword(Database& db, int user_id) {
    std::string description;
    std::cout << "Введите описание (сайт) для удаления: ";
    std::getline(std::cin, description);
    
    if (db.removePassword(user_id, description)) {
        std::cout << "Запись удалена!" << std::endl;
    }
}

void listPasswords(Database& db, Crypto& crypto, int user_id) {
    std::vector<PasswordEntry> entries;
    if (!db.getPasswords(user_id, entries)) {
        std::cout << "Ошибка получения записей!" << std::endl;
        return;
    }

    if (entries.empty()) {
        std::cout << "Список паролей пуст." << std::endl;
        return;
    }
    
    std::cout << "Сохраненные записи:" << std::endl;
    for (const auto& entry : entries) {
        try {
            std::string decrypted = crypto.decrypt(entry.password);
            std::cout << "Сайт: " << entry.description 
                      << " | Логин: " << entry.login 
                      << " | Пароль: " << decrypted << std::endl;
        } catch (const std::exception& e) {
            std::cout << "Сайт: " << entry.description 
                      << " | Логин: " << entry.login 
                      << " | Ошибка расшифровки: " << e.what() << std::endl;
        }
    }
}

void exportPasswords(Database& db, Crypto& crypto, int user_id) {
    std::vector<PasswordEntry> entries;
    if (!db.getPasswords(user_id, entries)) {
        std::cout << "Ошибка получения записей!" << std::endl;
        return;
    }

    std::vector<PasswordEntry> decrypted_entries;
    for (const auto& entry : entries) {
        PasswordEntry decrypted_entry = entry;
        try {
            decrypted_entry.password = crypto.decrypt(entry.password);
            decrypted_entries.push_back(decrypted_entry);
        } catch (const std::exception& e) {
            std::cout << "Ошибка расшифровки записи: " << entry.description << std::endl;
        }
    }

    try {
        ImportExport::exportPasswords("import_export.json", decrypted_entries);
        std::cout << "Пароли экспортированы в import_export.json" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "Ошибка экспорта: " << e.what() << std::endl;
    }
}

void importPasswords(Database& db, Crypto& crypto, int user_id) {
    try {
        std::vector<PasswordEntry> entries = ImportExport::importPasswords("import_export.json");
        for (auto& entry : entries) {
            entry.password = crypto.encrypt(entry.password);
            if (!db.addPassword(user_id, entry)) {
                std::cout << "Ошибка добавления записи: " << entry.description << std::endl;
            }
        }
        std::cout << "Пароли импортированы из import_export.json" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "Ошибка импорта: " << e.what() << std::endl;
    }
}

int main() {
    srand(time(0));
    Database db("password_manager.db");
    if (!db.initialize()) {
        std::cerr << "Ошибка инициализации базы данных!" << std::endl;
        return 1;
    }

    // Инициализация кэша TOTP
    try {
        MMAPUtils::initTOTPCache("2fa_cache.bin", 1024);
    } catch (const std::exception& e) {
        std::cerr << "Ошибка инициализации кэша TOTP: " << e.what() << std::endl;
        return 1;
    }

    std::string password;
    std::cout << "Введите мастер-пароль для шифрования: ";
    std::getline(std::cin, password);

    Crypto crypto(password, "master_key.bin");
    int user_id = -1;
    if (!authenticate(db, crypto, user_id)) {
        MMAPUtils::cleanupTOTPCache("2fa_cache.bin");
        return 0;
    }

    while (true) {
        showMainMenu();
        int choice = Exceptions::getValidNumber(1, 6);
        switch (choice) {
            case 1:
                addPassword(db, crypto, user_id);
                break;
            case 2:
                removePassword(db, user_id);
                break;
            case 3:
                listPasswords(db, crypto, user_id);
                break;
            case 4:
                exportPasswords(db, crypto, user_id);
                break;
            case 5:
                importPasswords(db, crypto, user_id);
                break;
            case 6:
                std::cout << "Выход..." << std::endl;
                MMAPUtils::cleanupTOTPCache("2fa_cache.bin");
                return 0;
        }
    }
    return 0;
}