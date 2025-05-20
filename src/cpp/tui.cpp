#include "../h/tui.h"
#include "../h/mmap_utils.h"
#include <ncursesw/ncurses.h>
#include <stdexcept>
#include <clocale>
#include <iostream>
#include <utility>
#include <qrencode.h>
#include <sstream>

TUI::TUI(const std::string& db_path, std::string  key_file, const std::string& cache_file)
        : db(new Database(db_path)), key_file(std::move(key_file)), cache_file(cache_file),
          current_user_id(0), is_authenticated(false), main_win(nullptr), input_win(nullptr), status_win(nullptr) {


    setlocale (LC_ALL, "");

    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    initColors();
    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    int main_height = LINES - 6;
    int input_height = 3;
    int status_height = 3;

    main_win = newwin(main_height, COLS, 0, 0);
    input_win = newwin(input_height, COLS, main_height, 0);
    status_win = newwin(status_height, COLS, main_height + input_height, 0);

    keypad(main_win, TRUE);
    keypad(input_win, TRUE);
    keypad(status_win, TRUE);
    refreshWindows();
    if (!db->initialize()) {
        showError("Failed to initialize the database");
        throw std::runtime_error("Database initialization failed");
    }
    MMAPUtils::initTOTPCache(cache_file, 100);
}

WINDOW* TUI::createCenteredWindow(int height, int width) {
    int start_y = (LINES - height) / 2;
    int start_x = (COLS - width) / 2;
    WINDOW* win = newwin(height, width, start_y, start_x);
    keypad(win, TRUE);
    box(win, 0, 0);
    return win;
}

TUI::~TUI() {
    delete db;
    delete crypto;
    delwin(main_win);
    delwin(input_win);
    delwin(status_win);
    endwin();
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
    int x = (max_x - static_cast<int>(text.length())) / 2;
    if (x < 0) x = 0;
    wattron(win, COLOR_PAIR(pair));
    mvwaddwstr(win, y, x, text.c_str()); // Используем широкие символы
    wattroff(win, COLOR_PAIR(pair));
}

void TUI::showMainMenu() {
    wclear(main_win);
    refreshWindows();
    box(main_win, 0, 0);
    centerText(main_win, 1, L"Password manager", PAIR_TITLE);
    centerText(main_win, 3, L"1. Registration", PAIR_MENU);
    centerText(main_win, 4, L"2. Log in", PAIR_MENU);
    centerText(main_win, 5, L"3. Log out", PAIR_MENU);
    wrefresh(main_win);
    const int choice = getValidNumber(1, 3, "Choose option: ");
    switch (choice) {
        case 1: handleRegister(); break;
        case 2: handleLogin(); break;
        case 3: exit(0);
        default:
            std::cout << "Invalid choice" << std::endl;
            break;
    }
}

std::string TUI::getInput(const std::string& prompt, bool echo_input) {
    const int MAX_INPUT_ = 256;
    char input[MAX_INPUT_];
    werase(input_win);
    box(input_win, 0, 0);
    mvwprintw(input_win, 1, 1, "%s", prompt.c_str());
    wrefresh(input_win);
    if (echo_input) {
        echo();
    } else {
        noecho();
    }
    wgetnstr(input_win, input, MAX_INPUT_ - 1);
    noecho();
    return std::string(input);
}

void TUI::handleLogin() {
    std::string username = getInput("Enter the user's name: ", true);
    std::string password = getInput("Enter the password: ", false);
    std::string password_hash = Crypto::hashPassword(password);
    std::string totp_secret;
    int user_id;

    if (db->authenticateUser(username, password_hash, user_id, totp_secret)) {
        if (totp_secret.empty()) {
            showError("An invalid TotP is a secret in the database. Please register again.");
            return;
        }
        std::string totp_code = getInput("Enter the TOTP code: ", true);
        if (MMAPUtils::isCodeInCache(cache_file, user_id, totp_code)) {
            showError("TOTP code has already been used.");
            return;
        }
        if (TOTP::verifyCode(totp_secret, totp_code)) {
            MMAPUtils::addTOTPCacheEntry(cache_file, user_id, totp_code);
            crypto = new Crypto(password, key_file);
            current_user_id = user_id;
            current_username = username;
            is_authenticated = true;
            showSuccess("The entrance is successful.");
        } else {
            showError("Inappropriate TOTP code.");
        }
    } else {
        showError("Invalid user name or password.");
    }
}

void TUI::handleRegister() {
    std::string username = getInput("Enter the user's name: ", true);
    std::string password = getInput("Enter the password: ", false);
    std::string password_hash = Crypto::hashPassword(password);
    std::string totp_secret = TOTP::generateSecret();

    // Показываем QR-код и секрет временно
    std::string totp_uri = "otpauth://totp/PasswordManager" + username + "?secret=" + totp_secret;
    std::wstring qr_code = generateQRCode(totp_uri);
    showTotpScreen(totp_secret, qr_code);
    std::string totp_code = getInput("Enter TOTP code to confirm: ", true);

    // Очищаем экран и возвращаемся в главное меню
    wclear(main_win);
    wclear(input_win);
    refreshWindows();

    if (TOTP::verifyCode(totp_secret, totp_code)) {
        if (db->registerUser(username, password_hash, totp_secret)) {
            showSuccess("Registration is successful.");
            resetUI();
        } else {
            showError("The user already exists or registration error.");
            resetUI();
        }
    } else {
        showError("Inappropriate TOTP code.");
        resetUI();
    }

    // Возврат к главному меню
    showMainMenu();
}

void TUI::resetUI() {
    wclear(main_win);
    wclear(input_win);
    wclear(status_win);
    refreshWindows();
    showMainMenu();
}

std::wstring TUI::generateQRCode(const std::string &data) {
    QRcode* qr = QRcode_encodeString(data.c_str(), 1, QR_ECLEVEL_M, QR_MODE_8, 1);
    if (!qr) return L"QR Error";

    std::wstring result;
    for (int y = 0; y < qr->width; y++) {
        for (int x = 0; x < qr->width; x++) {
            // Используем широкие символы
            result += (qr->data[y * qr->width + x] & 1) ? L"██" : L"  ";
        }
        result += L"\n";
    }
    QRcode_free(qr);
    return result;
}

void TUI::showTotpScreen(const std::string& totp_secret, const std::wstring& qr_code) {
    wclear(main_win);
    box(main_win, 0, 0);

    int max_y, max_x;
    getmaxyx(main_win, max_y, max_x); // Получаем размеры окна

    // Рассчитываем позиции
    const int qr_width = qr_code.find(L'\n'); // Ширина QR-кода (первая строка)
    const int text_x = qr_width + 4; // Позиция текста справа от QR-кода

    // Выводим QR-код слева
    std::wistringstream qr_stream(qr_code);
    std::wstring line;
    int y = 1;
    while (std::getline(qr_stream, line)) {
        mvwaddwstr(main_win, y, 2, line.c_str()); // Отступ 2 символа слева
        y++;
    }

    // Выводим TOTP-секрет справа
    std::wstring w_secret = L"TOTP Secret:\n" + std::wstring(totp_secret.begin(), totp_secret.end());
    std::wistringstream secret_stream(w_secret);
    y = 1;
    while (std::getline(secret_stream, line)) {
        mvwaddwstr(main_win, y, text_x, line.c_str());
        y++;
    }

    wrefresh(main_win);
}

void TUI::handleRemovePassword() {
    if (!is_authenticated) {
        showError("First enter the system.");
        return;
    }
    std::string description = getInput("Enter the name of the service for deleting: ", true);
    if (db->removePassword(current_user_id, description)) {
        showSuccess("The password is removed successfully.");
    } else {
        showError("A password was not found or a removal error.");
    }
}

void TUI::handleViewPasswords() {
    if (!is_authenticated) {
        showError("First enter the system.");
        return;
    }
    std::vector<PasswordEntry> passwords;
    if (db->getPasswords(current_user_id, passwords)) {
        wclear(main_win);
        box(main_win, 0, 0);
        int y = 1;
        for (const auto& pass : passwords) {
            std::string decrypted_password = crypto->decrypt(pass.password);
            mvwprintw(main_win, y++, 1, "%s - %s: %s", pass.description.c_str(), pass.login.c_str(), decrypted_password.c_str());
        }
        wrefresh(main_win);
        wgetch(main_win);
    } else {
        showError("Error when receiving passwords.");
    }
}

void TUI::handleGeneratePassword() {
    std::string generated_password = generatePassword(16, true, true, true, true);
    showStatus("Generated password: " + generated_password);
    if (confirmAction("Want to add this password to the database?")) {
        std::string description = getInput("Enter the name of the service: ", true);
        std::string login = getInput("Enter the user's name: ", true);
        std::string encrypted_password = crypto->encrypt(generated_password);
        PasswordEntry entry = {description, login, encrypted_password};
        if (db->addPassword(current_user_id, entry)) {
            showSuccess("The password is added successfully.");
        } else {
            showError("Error when adding a password.");
        }
    }
}

void TUI::showPasswordGenWindow(int& length, bool& lower, bool& upper, bool& digits, bool& symbols) {
    WINDOW* gen_win = createCenteredWindow(12, 50);
    keypad(gen_win, TRUE);
    box(gen_win, 0, 0);

    // Вывод параметров в новом окне
    mvwprintw(gen_win, 1, 2, "Password Generation Settings:");
    mvwprintw(gen_win, 3, 2, "Length (8-64): ");
    mvwprintw(gen_win, 4, 2, "Include lowercase? [ ]");
    mvwprintw(gen_win, 5, 2, "Include uppercase? [ ]");
    mvwprintw(gen_win, 6, 2, "Include digits?    [ ]");
    mvwprintw(gen_win, 7, 2, "Include symbols?   [ ]");

    // Ввод длины
    echo();
    mvwscanw(gen_win, 3, 17, "%d", &length);
    noecho();

    // Ввод параметров
    const int y_start = 4;
    bool options[4] = {lower, upper, digits, symbols};
    for (int i = 0; i < 4; i++) {
        mvwaddch(gen_win, y_start + i, 19, options[i] ? 'X' : ' ');
        wmove(gen_win, y_start + i, 19);
        int ch;
        while ((ch = wgetch(gen_win)) != '\n') {
            if (ch == ' ') {
                options[i] = !options[i];
                mvwaddch(gen_win, y_start + i, 19, options[i] ? 'X' : ' ');
            }
        }
    }

    lower = options[0];
    upper = options[1];
    digits = options[2];
    symbols = options[3];

    wrefresh(gen_win);
    delwin(gen_win);
}

void TUI::handleImportExport() {

    WINDOW* menu_win = createCenteredWindow(8, 40);
    mvwprintw(menu_win, 1, 2, "1. Import");
    mvwprintw(menu_win, 2, 2, "2. Export");
    wrefresh(menu_win);

    int choice = getValidNumber(1, 2, "Choose action: ");

    // Очистка модального окна
    werase(menu_win);
    wrefresh(menu_win);
    delwin(menu_win);
    
    if (choice == 1) {
        std::string file_path = getInput("Enter the path to the import: ", true);
        std::vector<PasswordEntry> entries = ImportExport::importPasswords(file_path);
        for (const auto& entry : entries) {
            if (!db->addPassword(current_user_id, entry)) {
                showError("Error when importing password: " + entry.description);
            }
        }
        showSuccess("Import is successful.");
    } else if (choice == 2) {
        std::vector<PasswordEntry> passwords;
        if (db->getPasswords(current_user_id, passwords)) {
            std::string file_path = getInput("Enter the path to the export file: ", true);
            ImportExport::exportPasswords(file_path, passwords);
            showSuccess("Export is successful.");
        } else {
            showError("Error when receiving passwords for export.");
        }
    }
}

int TUI::getValidNumber(int min, int max, const std::string& prompt) {
    while (true) {
        std::string input = getInput(prompt, true);
        try {
            int number = std::stoi(input);
            if (number >= min && number <= max) {
                return number;
            } else {
                showError("The number outside the range. Please enter the number from " + std::to_string(min) + " to " + std::to_string(max) + ".");
            }
        } catch (const std::invalid_argument&) {
            showError("Inadmissible input. Please enter the number.");
        } catch (const std::out_of_range&) {
            showError("The number is too large. Please enter a smaller number.");
        }
    }
}

// Измененное меню после входа
void TUI::showAuthenticatedMenu() {
    wclear(main_win);
    box(main_win, 0, 0);
    std::wstring welcome = L"Welcome, " + std::wstring(current_username.begin(), current_username.end());
    centerText(main_win, 1, welcome, PAIR_TITLE);
    centerText(main_win, 3, L"1. Password List", PAIR_MENU);
    centerText(main_win, 4, L"2. Import/Export", PAIR_MENU);
    centerText(main_win, 5, L"3. Logout", PAIR_MENU);
    wrefresh(main_win);
    int choice = getValidNumber(1, 3, "Choose option: ");
    switch (choice) {
        case 1: handlePasswordManagement(); break;
        case 2: handleImportExport(); break;
        case 3:
            is_authenticated = false;
            current_user_id = 0;
            current_username.clear();
            delete crypto;
            crypto = nullptr;
            break;
        default:
            showError("Invalid choice");
            break;
    }
}

// Новое меню управления паролями
void TUI::showPasswordManagementMenu() {
    wclear(main_win);
    box(main_win, 0, 0);
    centerText(main_win, 1, L"Password Management", PAIR_TITLE);
    centerText(main_win, 3, L"1. Add Password", PAIR_MENU);
    centerText(main_win, 4, L"2. Delete Password", PAIR_MENU);
    centerText(main_win, 5, L"3. Back", PAIR_MENU);
    wrefresh(main_win);
}

void TUI::handlePasswordManagement() {
    WINDOW* list_win = subwin(main_win, LINES - 8, COLS - 4, 1, 2);
    keypad(list_win, TRUE);

    // Функция обновления списка паролей
    auto updateList = [&]() {
        werase(list_win);
        box(list_win, 0, 0);
        std::vector<PasswordEntry> passwords;
        if (db->getPasswords(current_user_id, passwords)) {
            if (passwords.empty()) {
                mvwprintw(list_win, 1, 2, "No passwords stored");
            } else {
                for (size_t i = 0; i < passwords.size(); ++i) {
                    std::string decrypted = crypto->decrypt(passwords[i].password);
                    mvwprintw(list_win, i+1, 2, "%2zu. %-20s %-15s %s",
                        i+1,
                        passwords[i].description.c_str(),
                        passwords[i].login.c_str(),
                        decrypted.c_str());
                }
            }
        }
        wrefresh(list_win);
    };

    updateList(); // Первоначальное отображение

    // Меню управления
    while (true) {
        WINDOW* menu_win = createCenteredWindow(8, 40);
        mvwprintw(menu_win, 1, 2, "1. Add Password");
        mvwprintw(menu_win, 2, 2, "2. Delete Password");
        mvwprintw(menu_win, 3, 2, "3. Back");
        wrefresh(menu_win);

        int choice = getValidNumber(1, 3, "");

        // Очистка модального окна
        werase(menu_win);
        wrefresh(menu_win);
        delwin(menu_win);

        switch (choice) {
            case 1: {
                WINDOW* input_window = createCenteredWindow(6, 50);
                handleAddPassword();
                delwin(input_window);
                updateList();
                break;
            }
            case 2: {
                handleRemovePassword();
                updateList();
                break;
            }
            case 3:
                delwin(list_win);
                return;
        }
    }
}


// Модифицированный обработчик добавления пароля
void TUI::handleAddPassword() {
    std::string description = getInput("Enter service name: ", true);
    std::string login = getInput("Enter username: ", true);

    // Выбор способа ввода пароля

    WINDOW* menu_win = createCenteredWindow(8, 40);
    mvwprintw(menu_win, 1, 2, "1. Enter password manually");
    mvwprintw(menu_win, 2, 2, "2. Generate Password");
    wrefresh(menu_win);

    int method = getValidNumber(1, 2,"Choose method: ");

    werase(menu_win);
    wrefresh(menu_win);
    delwin(menu_win);

    std::string password;
    if (method == 1) {
        password = getInput("Enter password: ", false);
    } else {
        // Параметры генерации
        int length = getValidNumber(8, 64, "Password length (8-64):");
        bool lower = confirmAction("Include lowercase letters?");
        bool upper = confirmAction("Include uppercase letters?");
        bool digits = confirmAction("Include digits? ");
        bool symbols = confirmAction("Include symbols?");

        password = generatePassword(length, lower, upper, digits, symbols);
        showStatus("Generated password: " + password);
    }

    // Добавление в БД
    std::string encrypted_password = crypto->encrypt(password);
    PasswordEntry entry = {description, login, encrypted_password};
    if (db->addPassword(current_user_id, entry)) {
        showSuccess("Password added successfully");
    } else {
        showError("Failed to add password");
    }
}

bool TUI::confirmAction(const std::string& prompt) const {
    wclear(input_win);
    box(input_win, 0, 0);
    mvwprintw(input_win, 1, 1, prompt.c_str());
    mvwprintw(input_win, 2, 1, " (y/n): ");
    wrefresh(input_win);
    int ch = wgetch(input_win);
    return ch == 'y' || ch == 'Y';
}

void TUI::showSuccess(const std::string& message) const {
    wclear(status_win);
    box(status_win, 0, 0);
    const std::wstring wmessage = L"✓ " + std::wstring(message.begin(), message.end());
    centerText(status_win, 1, wmessage, PAIR_SUCCESS);
    wrefresh(status_win);
    wgetch(status_win);
}

void TUI::showError(const std::string& message) const {
    wclear(status_win);
    box(status_win, 0, 0);
    const std::wstring wmessage = L"✗ " + std::wstring(message.begin(), message.end());
    centerText(status_win, 1, wmessage, PAIR_ERROR);
    wrefresh(status_win);
    wgetch(status_win);
}

void TUI::showStatus(const std::string& message) const {
    wclear(status_win);
    box(status_win, 0, 0);
    const auto wmessage = std::wstring(message.begin(), message.end());
    centerText(status_win, 1, wmessage, PAIR_DEFAULT);
    wrefresh(status_win);
    wgetch(status_win);
}

void TUI::refreshWindows() {
    wrefresh(main_win);
    wrefresh(input_win);
    wrefresh(status_win);
}

void TUI::run() {
    while (true) {
        if (!is_authenticated) {
            showMainMenu();
        } else {
            showAuthenticatedMenu();
        }
    }
}