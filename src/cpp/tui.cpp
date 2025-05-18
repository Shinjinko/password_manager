#include "../h/tui.h"
#include "../h/mmap_utils.h"
#include <ncursesw/cursesw.h>
#include <stdexcept>
#include <clocale>
#include <iostream>
#include <utility>


TUI::TUI(const std::string& db_path, std::string  key_file, const std::string& cache_file)
        : db(new Database(db_path)), key_file(std::move(key_file)), cache_file(cache_file),
          current_user_id(0), is_authenticated(false), main_win(nullptr), input_win(nullptr), status_win(nullptr) {
    setlocale(LC_ALL, "");
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    initColors();
    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);
    main_win = newwin(max_y - 5, max_x, 0, 0);
    input_win = newwin(3, max_x, max_y - 5, 0);
    status_win = newwin(2, max_x, max_y - 2, 0);
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
    mvwaddnwstr(win, y, x, text.c_str(), text.length());
    wattroff(win, COLOR_PAIR(pair));
}

void TUI::showMainMenu() {
    wclear(main_win);
    box(main_win, 0, 0);
    centerText(main_win, 1, L"Password manager", PAIR_TITLE);
    centerText(main_win, 3, L"1. Registration", PAIR_MENU);
    centerText(main_win, 4, L"2. Log in", PAIR_MENU);
    centerText(main_win, 5, L"3. Log out", PAIR_MENU);
    wrefresh(main_win);
    int choice = getValidNumber(1, 3, "Choose option: ");
    switch (choice) {
        case 1: handleRegister(); break;
        case 2: handleLogin(); break;
        case 3: exit(0);
        default:
            std::cout << "Invalid choice" << std::endl;
            break;
    }
}

void TUI::showAuthenticatedMenu() {
    wclear(main_win);
    box(main_win, 0, 0);
    std::wstring welcome = L"Welcome, " + std::wstring(current_username.begin(), current_username.end());
    centerText(main_win, 1, welcome, PAIR_TITLE);
    centerText(main_win, 3, L"1. Add password", PAIR_MENU);
    centerText(main_win, 4, L"2. Delete password", PAIR_MENU);
    centerText(main_win, 5, L"3. View passwords", PAIR_MENU);
    centerText(main_win, 6, L"4. Generate the password", PAIR_MENU);
    centerText(main_win, 7, L"5. Import/export passwords", PAIR_MENU);
    centerText(main_win, 8, L"6. Exit", PAIR_MENU);
    wrefresh(main_win);
    int choice = getValidNumber(1, 6, "Choose option: ");
    switch (choice) {
        case 1: handleAddPassword(); break;
        case 2: handleRemovePassword(); break;
        case 3: handleViewPasswords(); break;
        case 4: handleGeneratePassword(); break;
        case 5: handleImportExport(); break;
        case 6: is_authenticated = false; current_user_id = 0; current_username.clear(); delete crypto; crypto = nullptr; break;
        default: std::cout << "Invalid choice" << std::endl;
            break;
    }
}

std::string TUI::getInput(const std::string& prompt, bool echo_input) {
    const int MAX_INPUT_ = 256;
    char input[MAX_INPUT_];
    wclear(input_win);
    box(input_win, 0, 0);
    mvwprintw(input_win, 1, 1, prompt.c_str());
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
    showStatus("Your TOTP secret: " + totp_secret);
    std::string totp_code = getInput("Enter the current TOTP code: ", true);
    if (TOTP::verifyCode(totp_secret, totp_code)) {
        if (db->registerUser(username, password_hash, totp_secret)) {
            showSuccess("Registration is successful.");
        } else {
            showError("The user already exists or registration error.");
        }
    } else {
        showError("Inappropriate TOTP code.");
    }
}

void TUI::handleAddPassword() {
    if (!is_authenticated) {
        showError("First enter the system.");
        return;
    }
    std::string description = getInput("Enter the name of the service: ", true);
    std::string login = getInput("Enter the user's name: ", true);
    std::string password = getInput("Enter the password: ", false);
    std::string encrypted_password = crypto->encrypt(password);
    PasswordEntry entry = {description, login, encrypted_password};
    if (db->addPassword(current_user_id, entry)) {
        showSuccess("The password is added successfully.");
    } else {
        showError("Error when adding a password.");
    }
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

void TUI::handleImportExport() {
    int choice = getValidNumber(1, 2, "1. Import\n2. Export\nChoose action: ");
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