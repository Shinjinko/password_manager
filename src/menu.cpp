#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>

struct PasswordEntry {
    std::string name;
    std::string password;
};

std::vector<PasswordEntry> passwordDatabase;

void showMenu() {
    std::cout << "\nМенеджер паролей CLI" << std::endl;
    std::cout << "1. Добавить пароль" << std::endl;
    std::cout << "2. Удалить пароль" << std::endl;
    std::cout << "3. Вывести список" << std::endl;
    std::cout << "4. Выйти" << std::endl;
    std::cout << "Выберите действие: ";
}

void addPassword() {
    PasswordEntry entry;
    std::cout << "Введите название записи: ";
    std::cin >> entry.name;
    std::cout << "Введите пароль: ";
    std::cin >> entry.password;
    passwordDatabase.push_back(entry);
    std::cout << "Пароль добавлен!" << std::endl;
}

void removePassword() {
    std::string name;
    std::cout << "Введите название записи для удаления: ";
    std::cin >> name;
    
    for (auto it = passwordDatabase.begin(); it != passwordDatabase.end(); ++it) {
        if (it->name == name) {
            passwordDatabase.erase(it);
            std::cout << "Пароль удален!" << std::endl;
            return;
        }
    }
    std::cout << "Запись не найдена!" << std::endl;
}

void listPasswords() {
    if (passwordDatabase.empty()) {
        std::cout << "Список паролей пуст." << std::endl;
        return;
    }
    
    std::cout << "Сохраненные пароли:" << std::endl;
    for (const auto& entry : passwordDatabase) {
        std::cout << "Название: " << entry.name << " | Пароль: " << entry.password << std::endl;
    }
}

int main() {
    int choice;
    while (true) {
        showMenu();
        std::cin >> choice;
        switch (choice) {
            case 1:
                addPassword();
                break;
            case 2:
                removePassword();
                break;
            case 3:
                listPasswords();
                break;
            case 4:
                std::cout << "Выход..." << std::endl;
                return 0;
            default:
                std::cout << "Некорректный ввод, попробуйте снова." << std::endl;
        }
    }
    return 0;
}

