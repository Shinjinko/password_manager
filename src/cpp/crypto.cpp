#include "../h/crypto.h"
#include "../h/mmap_utils.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <stdexcept>
#include <cstring>
#include <vector>

Crypto::Crypto(const std::string& password, const std::string& key_file) {
    // Проверяем, существует ли мастер-ключ
    bool key_exists = false;
    struct stat st;
    if (stat(key_file.c_str(), &st) != -1) {
        key_exists = true;
    }

    if (key_exists) {
        master_key = MMAPUtils::loadMasterKey(key_file, password);
    } else {
        // Генерируем новый мастер-ключ
        unsigned char key[32];
        if (RAND_bytes(key, 32) != 1) {
            throw std::runtime_error("Failed to generate master key");
        }
        master_key = std::string((char*)key, 32);
        MMAPUtils::storeMasterKey(key_file, master_key, password);
    }
}

Crypto::~Crypto() {
    // Очищаем мастер-ключ из памяти
    if (!master_key.empty()) {
        OPENSSL_cleanse(&master_key[0], master_key.size());
    }
}

std::string Crypto::encrypt(const std::string& data) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    unsigned char iv[12];
    if (RAND_bytes(iv, 12) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to generate IV");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, (unsigned char*)master_key.c_str(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize AES-256-GCM");
    }

    std::vector<unsigned char> ciphertext(data.size() + 16);
    int len, ciphertext_len;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)data.c_str(), data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt data");
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }
    ciphertext_len += len;

    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get GCM tag");
    }

    EVP_CIPHER_CTX_free(ctx);

    // Формат: IV (12) + шифрованный текст + тег (16)
    std::string result(12 + ciphertext_len + 16, 0);
    memcpy(&result[0], iv, 12);
    memcpy(&result[12], ciphertext.data(), ciphertext_len);
    memcpy(&result[12 + ciphertext_len], tag, 16);

    return result;
}

std::string Crypto::decrypt(const std::string& data) {
    if (data.size() < 12 + 16) throw std::runtime_error("Invalid encrypted data size");

    unsigned char iv[12];
    memcpy(iv, data.c_str(), 12);
    size_t ciphertext_len = data.size() - 12 - 16;
    std::vector<unsigned char> ciphertext(ciphertext_len);
    memcpy(ciphertext.data(), data.c_str() + 12, ciphertext_len);
    unsigned char tag[16];
    memcpy(tag, data.c_str() + 12 + ciphertext_len, 16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, (unsigned char*)master_key.c_str(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize AES-256-GCM");
    }

    std::vector<unsigned char> plaintext(ciphertext_len);
    int len, plaintext_len;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt data");
    }
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set GCM tag");
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize decryption");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}

std::string Crypto::hashPassword(const std::string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password.c_str(), password.length(), hash);
    char hex[2 * SHA256_DIGEST_LENGTH + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(hex + 2 * i, "%02x", hash[i]);
    }
    hex[2 * SHA256_DIGEST_LENGTH] = '\0';
    return std::string(hex);
}
