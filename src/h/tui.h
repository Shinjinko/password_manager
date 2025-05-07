#ifndef TUI_H
#define TUI_H

#include <ncurses.h>
#include <string>
#include <vector>
#include "../h/database.h"
#include "../h/crypto.h"
#include "../h/totp.h"
#include "../h/pass_gen.h"
#include "../h/import_export.h"

class TUI {
public:
    TUI(const std::string& db_path, const std::string& key_file, const std::string& cache_file);
    ~TUI();
    void run();

private:
    Database* db;
    Crypto* crypto;
    std::string key_file;
    std::string cache_file;
    int current_user_id;
    std::string current_username;
    bool is_authenticated;

    // Window management
    WINDOW* main_win;
    WINDOW* input_win;
    WINDOW* status_win;

    // Color pairs
    enum ColorPairs {
        PAIR_DEFAULT = 1,
        PAIR_TITLE,
        PAIR_MENU,
        PAIR_SUCCESS,
        PAIR_ERROR,
        PAIR_WARNING,
        PAIR_HIGHLIGHT
    };

    // Menu navigation
    void showMainMenu();
    void showAuthenticatedMenu();
    void handleRegister();
    void handleLogin();
    void handleAddPassword();
    void handleRemovePassword();
    void handleViewPasswords();
    void handleGeneratePassword();
    void handleImportExport();
    void showError(const std::string& message);
    void showStatus(const std::string& message);
    void showSuccess(const std::string& message);

    // Centered text utilities
    void centerText(WINDOW* win, int y, const std::wstring& text, int pair = PAIR_DEFAULT);
    void centerText(WINDOW* win, int y, const std::string& text, int pair = PAIR_DEFAULT);

    // Input handling
    std::string getInput(const std::string& prompt);
    int getValidNumber(int min, int max, const std::string& prompt);
    bool confirmAction(const std::string& prompt);
    bool confirmActionW(const std::wstring& prompt);

    // Utility
    void clearInputWindow();
    void refreshWindows();
    void initColors();
};

#endif // TUI_H