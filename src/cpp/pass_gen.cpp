#include "../h/pass_gen.h"
#include <cstdlib>

std::string generatePassword(int length, bool useLower, bool useUpper, bool useDigits, bool useSymbols) {
    std::string chars;
    if (useLower) chars += "abcdefghijklmnopqrstuvwxyz";
    if (useUpper) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (useDigits) chars += "0123456789";
    if (useSymbols) chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";

    if (chars.empty()) {
        return "";
    }

    std::string password;
    for (int i = 0; i < length; ++i) {
        password += chars[rand() % chars.length()];
    }
    return password;
}
