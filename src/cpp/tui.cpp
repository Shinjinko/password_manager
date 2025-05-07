#include "../h/tui.h"
#include "../h/mmap_utils.h"
#include <stdexcept>
#include <sstream>
#include <iostream>
#include <locale.h>
#include <wchar.h>

TUI::TUI(const std::string& db_path, const std::string& key_file, const std::string& cache_file)
    : db(new Database(db_path)), key_file(key_file), cache_file(cache_file),
      current_user_id(0), is_authenticated(false), main_win(nullptr), input_win(nullptr), status_win(nullptr) {
    // Установка локали для поддержки UTF-8
    setlocale(LC_ALL, "");

    // Инициализация ncurses
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0); // Hide cursor

    // Initialize colors
    initColors();

    // Создание окон
    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);
    main_win = newwin(max_y - 5, max_x, 0, 0);
    input_win = newwin(3, max_x, max_y - 5, 0);
    status_win = newwin(2, max_x, max_y - 2, 0);
    
    // Enable keypad for windows
    keypad(main_win, TRUE);
    keypad(input_win, TRUE);
    keypad(status_win, TRUE);
    
    refreshWindows();
    
    // Инициализация базы данных
    if (!db->initialize()) {
        showError("Не удалось инициализировать базу данных");
        throw std::runtime_error("Database initialization failed");
    }

    // Инициализация кэша TOTP
    MMAPUtils::initTOTPCache(cache_file, 100);
}

void TUI::initColors() {
    if (has_colors()) {
        start_color();
        init_pair(PAIR_DEFAULT, COLOR_WHITE, COLOR_BLACK);
        init_pair(PAIR_TITLE, COLOR_CYAN, COLOR_BLACK);
        init_pair(PAIR_MENU, COLOR_YELLOW, COLOR_BLACK);
        init_pair(PAIR_SUCCESS, COLOR_GREEN, COLOR_BLACK);
        init_pair(PAIR_ERROR, COLOR_RED, COLOR_BLACK);
        init_pair(PAIR_WARNING, COLOR_MAGENTA, COLOR_BLACK);
        init_pair(PAIR_HIGHLIGHT, COLOR_BLUE, COLOR_BLACK);
    }
}

void TUI::centerText(WINDOW* win, int y, const std::wstring& text, int pair) {
    int max_x = getmaxx(win);
    int x = (max_x - text.length()) / 2;
    if (x < 0) x = 0;
    wattron(win, COLOR_PAIR(pair));
    mvwaddwstr(win, y, x, text.c_str());
    wattroff(win, COLOR_PAIR(pair));
}

void TUI::centerText(WINDOW* win, int y, const std::string& text, int pair) {
    centerText(win, y, std::wstring(text.begin(), text.end()), pair);
}

void TUI::showMainMenu() {
    wclear(main_win);
    box(main_win, 0, 0);
    
    centerText(main_win, 1, L"Менеджер паролей", PAIR_TITLE);
    centerText(main_win, 3, L"1. Регистрация", PAIR_MENU);
    centerText(main_win, 4, L"2. Вход", PAIR_MENU);
    centerText(main_win, 5, L"3. Выход", PAIR_MENU);
    
    wrefresh(main_win);
    
    int choice = getValidNumber(1, 3, "Выберите опцию: ");
    switch (choice) {
        case 1: handleRegister(); break;
        case 2: handleLogin(); break;
        case 3: exit(0);
    }
}

void TUI::showAuthenticatedMenu() {
    wclear(main_win);
    box(main_win, 0, 0);
    
    std::wstring welcome = L"Добро пожаловать, " + std::wstring(current_username.begin(), current_username.end());
    centerText(main_win, 1, welcome, PAIR_TITLE);
    
    centerText(main_win, 3, L"1. Добавить пароль", PAIR_MENU);
    centerText(main_win, 4, L"2. Удалить пароль", PAIR_MENU);
    centerText(main_win, 5, L"3. Просмотреть пароли", PAIR_MENU);
    centerText(main_win, 6, L"4. Сгенерировать пароль", PAIR_MENU);
    centerText(main_win, 7, L"5. Импорт/Экспорт паролей", PAIR_MENU);
    centerText(main_win, 8, L"6. Выход", PAIR_MENU);
    
    wrefresh(main_win);
    
    int choice = getValidNumber(1, 6, "Выберите опцию: ");
    switch (choice) {
        case 1: handleAddPassword(); break;
        case 2: handleRemovePassword(); break;
        case 3: handleViewPasswords(); break;
        case 4: handleGeneratePassword(); break;
        case 5: handleImportExport(); break;
        case 6: is_authenticated = false; current_user_id = 0; current_username.clear(); delete crypto; crypto = nullptr; break;
    }
}

void TUI::handleLogin() {
    std::string username = getInput("Введите имя пользователя: ");
    std::string password = getInput("Введите пароль: ");
    std::string password_hash = Crypto("", key_file).hashPassword(password);
    std::string totp_secret;
    int user_id;
    
    if (db->authenticateUser(username, password_hash, user_id, totp_secret)) {
        if (totp_secret.empty()) {
            showError("Недействительный TOTP секрет в базе данных. Пожалуйста, зарегистрируйтесь заново.");
            return;
        }
        
        std::string totp_code = getInput("Введите TOTP код: ");
        if (MMAPUtils::isCodeInCache(cache_file, user_id, totp_code)) {
            showError("TOTP код уже использован.");
            return;
        }
        
        if (TOTP::verifyCode(totp_secret, totp_code)) {
            MMAPUtils::addTOTPCacheEntry(cache_file, user_id, totp_code);
            crypto = new Crypto(password, key_file);
            current_user_id = user_id;
            current_username = username;
            is_authenticated = true;
            showSuccess("Вход выполнен успешно.");
        } else {
            showError("Недействительный TOTP код.");
        }
    } else {
        showError("Недействительное имя пользователя или пароль.");
    }
}

void TUI::showSuccess(const std::string& message) {
    wclear(status_win);
    box(status_win, 0, 0);
    std::wstring wmessage = L"✓ " + std::wstring(message.begin(), message.end());
    centerText(status_win, 1, wmessage, PAIR_SUCCESS);
    wrefresh(status_win);
    wgetch(status_win);
}

void TUI::showError(const std::string& message) {
    wclear(status_win);
    box(status_win, 0, 0);
    std::wstring wmessage = L"✗ " + std::wstring(message.begin(), message.end());
    centerText(status_win, 1, wmessage, PAIR_ERROR);
    wrefresh(status_win);
    wgetch(status_win);
}

void TUI::showStatus(const std::string& message) {
    wclear(status_win);
    box(status_win, 0, 0);
    std::wstring wmessage = std::wstring(message.begin(), message.end());
    centerText(status_win, 1, wmessage, PAIR_DEFAULT);
    wrefresh(status_win);
    wgetch(status_win);
}

// ... (rest of the implementation remains the same)