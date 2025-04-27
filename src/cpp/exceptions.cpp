#include "../h/exceptions.h"
#include <iostream>
#include <limits>

namespace Exceptions {
    int getValidNumber(int min, int max, const std::string& prompt) {
        int number;
        while (true) {
            std::cout << prompt;
            if (std::cin >> number) {
                if (number >= min && number <= max) {
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Очистка буфера
                    return number;
                } else {
                    std::cout << "Ошибка: введите число от " << min << " до " << max << "!" << std::endl;
                }
            } else {
                std::cout << "Ошибка: введите число!" << std::endl;
                std::cin.clear();
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            }
        }
    }
}