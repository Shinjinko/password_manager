#include "../h/tui.h"
#include <stdexcept>
#include <iostream>
#include <ostream>
#include <ncursesw/ncurses.h>
#include <clocale>

int main() {
    setlocale(LC_ALL, "");
    initscr();
    try {
        TUI tui("passwords.db", "master_key.bin", "totp_cache.bin");
        tui.run();
    } catch (const std::exception& e) {
        endwin();
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}