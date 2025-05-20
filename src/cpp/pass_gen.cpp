#include "../h/pass_gen.h"
#include <cstdlib>
#include <stdexcept>

std::string generatePassword(int length, bool useLower, bool useUpper, bool useDigits, bool useSymbols) {
    if (length < 8 || length > 64)
        throw std::invalid_argument("Invalid length (8-64)");

    std::string chars;
    if (useLower) chars += "abcdefghijklmnopqrstuvwxyz";
    if (useUpper) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (useDigits) chars += "0123456789";
    if (useSymbols) chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";

    if (chars.empty())
        throw std::logic_error("At least one character set must be selected");

    std::string password;
    for (int i = 0; i < length; ++i) {
        password += chars[rand() % chars.length()];
    }
    return password;
}
