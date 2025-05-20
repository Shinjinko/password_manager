#ifndef TUI_H
#define TUI_H

#include <ncurses.h>
#include <string>
#include "../h/database.h"
#include "../h/crypto.h"
#include "../h/totp.h"
#include "../h/pass_gen.h"
#include "../h/import_export.h"

class TUI {
public:
    TUI(const std::string& db_path, std::string  key_file, const std::string& cache_file);

    WINDOW *createCenteredWindow(int height, int width);

    ~TUI();
    void run();

private:
    Database* db;
    Crypto* crypto{};
    std::string key_file;
    std::string cache_file;
    int current_user_id;
    std::string current_username;
    bool is_authenticated;


    bool is_pending_totp_confirmation = false; // Новый флаг
    enum class State {
        MainMenu,
        ShowingQR,
        PendingTOTPConfirmation
    };
    State current_state = State::MainMenu;

    struct {
        std::string username;
        std::string password_hash;
        std::string totp_secret;
    } registration_data;

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

    void resetUI();
    void handlePasswordManagement();
    void showPasswordManagementMenu();
    void handleLogin();
    void handleAddPassword();
    void handleRemovePassword();
    void handleViewPasswords();
    void handleGeneratePassword();

    void showPasswordGenWindow(int &length, bool &lower, bool &upper, bool &digits, bool &symbols);

    void handleImportExport();
    void showError(const std::string& message) const;
    void showStatus(const std::string& message) const;
    void showSuccess(const std::string& message) const;

    static std::wstring generateQRCode(const std::string &data);
    void showTotpScreen(const std::string &totp_secret, const std::wstring &qr_code);

    // Centered text utilities
    static void centerText(WINDOW* win, int y, const std::wstring& text, int pair = PAIR_DEFAULT);
    static void centerText(WINDOW* win, int y, const std::string& text, int pair = PAIR_DEFAULT);

    // Input handling
    std::string getInput(const std::string& prompt, bool echo_input);
    int getValidNumber(int min, int max, const std::string& prompt);
    bool confirmAction(const std::string& prompt) const;
    bool confirmActionW(const std::wstring& prompt);

    // Utility
    void clearInputWindow();
    void refreshWindows();
    static void initColors();
};

#endif // TUI_H