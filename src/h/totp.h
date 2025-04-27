#ifndef TOTP_H
#define TOTP_H

#include <string>

class TOTP {
public:
    // Генерирует base32-закодированный секрет
    static std::string generateSecret();
    // Генерирует TOTP-код на основе секрета и текущего времени
    static std::string generateCode(const std::string& secret);
    // Проверяет TOTP-код
    static bool verifyCode(const std::string& secret, const std::string& code);
};

#endif // TOTP_H