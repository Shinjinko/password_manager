#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>

class Crypto {
public:
    Crypto(const std::string& password, const std::string& key_file = "master_key.bin");
    ~Crypto();
    std::string encrypt(const std::string& data);
    std::string decrypt(const std::string& data);
    std::string hashPassword(const std::string& password);
private:
    std::string master_key; // Мастер-ключ для AES-256-GCM
};

#endif // CRYPTO_H