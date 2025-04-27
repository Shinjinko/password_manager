#include "../h/totp.h"
#include <liboath/oath.h>
#include <stdexcept>
#include <random>
#include <ctime>
#include <iostream>

std::string TOTP::generateSecret() {
    const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 31);

    char secret[17];
    for (int i = 0; i < 16; ++i) {
        secret[i] = alphabet[dis(gen)];
    }
    secret[16] = '\0';

    char* encoded = nullptr;
    size_t encoded_len = 0;
    if (oath_base32_encode(secret, 16, &encoded, &encoded_len) != OATH_OK) {
        if (encoded) free(encoded);
        throw std::runtime_error("Failed to encode TOTP secret");
    }

    std::string result(encoded, encoded_len);
    free(encoded);
    return result;
}

bool TOTP::verifyCode(const std::string& secret, const std::string& code) {
    // Проверяем формат секрета и кода
    if (secret.empty() || code.empty()) {
        std::cerr << "TOTP: Пустой секрет или код" << std::endl;
        return false;
    }

    // Декодируем Base32 секрет
    char* decoded_secret = nullptr;
    size_t decoded_len = 0;
    int rc = oath_base32_decode(secret.c_str(), secret.length(), &decoded_secret, &decoded_len);
    if (rc != OATH_OK || decoded_secret == nullptr) {
        std::cerr << "TOTP: Ошибка декодирования секрета, rc=" << rc << std::endl;
        if (decoded_secret) free(decoded_secret);
        return false;
    }

    // Генерируем TOTP-код
    time_t now = time(nullptr);
    char totp_code[7];
    rc = oath_totp_generate(decoded_secret, decoded_len, now, 30, 0, 6, totp_code);
    free(decoded_secret);

    if (rc != OATH_OK) {
        std::cerr << "TOTP: Ошибка генерации кода, rc=" << rc << std::endl;
        return false;
    }

    // Сравниваем коды
    bool match = (code == totp_code);
    if (!match) {
        std::cerr << "TOTP: Код не совпадает." << std::endl;
    }

    return match;
}
