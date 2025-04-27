#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#include <string>

namespace Exceptions {
    // Получает корректное число в заданном диапазоне
    int getValidNumber(int min, int max, const std::string& prompt = "Выберите действие: ");
}

#endif // EXCEPTIONS_H