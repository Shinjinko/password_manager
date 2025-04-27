#include "../h/mmap_utils.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdexcept>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iostream>

void MMAPUtils::initTOTPCache(const std::string& cache_file, size_t max_entries) {
    int fd = open(cache_file.c_str(), O_RDWR | O_CREAT, 0600);
    if (fd == -1) throw std::runtime_error("Failed to open TOTP cache file");

    size_t size = max_entries * sizeof(TOTPCacheEntry);
    if (ftruncate(fd, size) == -1) {
        close(fd);
        throw std::runtime_error("Failed to set TOTP cache file size");
    }

    void* addr = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        close(fd);
        throw std::runtime_error("Failed to mmap TOTP cache");
    }

    memset(addr, 0, size); // Очищаем кэш
    munmap(addr, size);
    close(fd);
}

bool MMAPUtils::addTOTPCacheEntry(const std::string& cache_file, int user_id, const std::string& code) {
    struct stat st;
    if (stat(cache_file.c_str(), &st) == -1) return false;

    int fd = open(cache_file.c_str(), O_RDWR);
    if (fd == -1) return false;

    size_t size = st.st_size;
    TOTPCacheEntry* entries = (TOTPCacheEntry*)mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (entries == MAP_FAILED) {
        close(fd);
        return false;
    }

    size_t max_entries = size / sizeof(TOTPCacheEntry);
    for (size_t i = 0; i < max_entries; ++i) {
        if (entries[i].user_id == 0) { // Пустая запись
            entries[i].user_id = user_id;
            strncpy(entries[i].code, code.c_str(), 7);
            entries[i].timestamp = time(nullptr);
            munmap(entries, size);
            close(fd);
            return true;
        }
    }

    munmap(entries, size);
    close(fd);
    return false;
}

bool MMAPUtils::isCodeInCache(const std::string& cache_file, int user_id, const std::string& code) {
    struct stat st;
    if (stat(cache_file.c_str(), &st) == -1) return false;

    int fd = open(cache_file.c_str(), O_RDONLY);
    if (fd == -1) return false;

    size_t size = st.st_size;
    TOTPCacheEntry* entries = (TOTPCacheEntry*)mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
    if (entries == MAP_FAILED) {
        close(fd);
        return false;
    }

    size_t max_entries = size / sizeof(TOTPCacheEntry);
    time_t now = time(nullptr);
    bool found = false;
    for (size_t i = 0; i < max_entries; ++i) {
        if (entries[i].user_id == user_id && strcmp(entries[i].code, code.c_str()) == 0) {
            if (now - entries[i].timestamp < 30) {
                found = true;
            } else {
                entries[i].user_id = 0; // Очищаем устаревшую запись
            }
        }
    }

    munmap(entries, size);
    close(fd);
    return found;
}

void MMAPUtils::cleanupTOTPCache(const std::string& cache_file) {
    struct stat st;
    if (stat(cache_file.c_str(), &st) == -1) return;

    int fd = open(cache_file.c_str(), O_RDWR);
    if (fd == -1) return;

    size_t size = st.st_size;
    TOTPCacheEntry* entries = (TOTPCacheEntry*)mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (entries == MAP_FAILED) {
        close(fd);
        return;
    }

    size_t max_entries = size / sizeof(TOTPCacheEntry);
    time_t now = time(nullptr);
    for (size_t i = 0; i < max_entries; ++i) {
        if (entries[i].user_id != 0 && now - entries[i].timestamp >= 30) {
            entries[i].user_id = 0;
        }
    }

    munmap(entries, size);
    close(fd);
}

void MMAPUtils::writeImportExportBuffer(const std::string& buffer_file, const std::string& data) {
    int fd = open(buffer_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) throw std::runtime_error("Failed to open import/export buffer file");

    size_t size = data.size();
    if (ftruncate(fd, size) == -1) {
        close(fd);
        throw std::runtime_error("Failed to set import/export buffer file size");
    }

    char* addr = (char*)mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        close(fd);
        throw std::runtime_error("Failed to mmap import/export buffer");
    }

    memcpy(addr, data.data(), size);
    munmap(addr, size);
    close(fd);
}

std::string MMAPUtils::readImportExportBuffer(const std::string& buffer_file) {
    struct stat st;
    if (stat(buffer_file.c_str(), &st) == -1) {
        throw std::runtime_error("Import/export buffer file does not exist");
    }

    int fd = open(buffer_file.c_str(), O_RDONLY);
    if (fd == -1) throw std::runtime_error("Failed to open import/export buffer file");

    size_t size = st.st_size;
    char* addr = (char*)mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        close(fd);
        throw std::runtime_error("Failed to mmap import/export buffer");
    }

    std::string result(addr, size);
    munmap(addr, size);
    close(fd);
    return result;
}

void MMAPUtils::storeMasterKey(const std::string& key_file, const std::string& key, const std::string& encryption_key) {
    // Генерируем ключ шифрования для мастер-ключа
    unsigned char derived_key[32];
    if (!PKCS5_PBKDF2_HMAC(encryption_key.c_str(), encryption_key.length(), 
                           nullptr, 0, 10000, EVP_sha256(), 32, derived_key)) {
        throw std::runtime_error("Failed to derive encryption key for master key");
    }

    // Инициализация AES-256-GCM
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    unsigned char iv[12];
    if (RAND_bytes(iv, 12) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to generate IV");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, derived_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize AES-256-GCM");
    }

    std::vector<unsigned char> ciphertext(key.size() + 16);
    int len, ciphertext_len;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)key.c_str(), key.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt master key");
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize master key encryption");
    }
    ciphertext_len += len;

    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get GCM tag");
    }

    EVP_CIPHER_CTX_free(ctx);

    // Сохраняем IV + шифрованный ключ + тег в файл через mmap
    size_t total_size = 12 + ciphertext_len + 16;
    int fd = open(key_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) throw std::runtime_error("Failed to open master key file");

    if (ftruncate(fd, total_size) == -1) {
        close(fd);
        throw std::runtime_error("Failed to set master key file size");
    }

    unsigned char* addr = (unsigned char*)mmap(nullptr, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        close(fd);
        throw std::runtime_error("Failed to mmap master key");
    }

    memcpy(addr, iv, 12);
    memcpy(addr + 12, ciphertext.data(), ciphertext_len);
    memcpy(addr + 12 + ciphertext_len, tag, 16);

    munmap(addr, total_size);
    close(fd);
}

std::string MMAPUtils::loadMasterKey(const std::string& key_file, const std::string& encryption_key) {
    struct stat st;
    if (stat(key_file.c_str(), &st) == -1) {
        throw std::runtime_error("Master key file does not exist");
    }

    if (st.st_size < 12 + 16) {
        throw std::runtime_error("Master key file is too small");
    }

    int fd = open(key_file.c_str(), O_RDONLY);
    if (fd == -1) throw std::runtime_error("Failed to open master key file");

    size_t size = st.st_size;
    unsigned char* addr = (unsigned char*)mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        close(fd);
        throw std::runtime_error("Failed to mmap master key");
    }

    unsigned char iv[12];
    memcpy(iv, addr, 12);
    size_t ciphertext_len = size - 12 - 16;
    std::vector<unsigned char> ciphertext(ciphertext_len);
    memcpy(ciphertext.data(), addr + 12, ciphertext_len);
    unsigned char tag[16];
    memcpy(tag, addr + 12 + ciphertext_len, 16);

    munmap(addr, size);
    close(fd);

    // Генерируем ключ расшифровки
    unsigned char derived_key[32];
    if (!PKCS5_PBKDF2_HMAC(encryption_key.c_str(), encryption_key.length(), 
                           nullptr, 0, 10000, EVP_sha256(), 32, derived_key)) {
        throw std::runtime_error("Failed to derive decryption key for master key");
    }

    // Инициализация AES-256-GCM
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, derived_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize AES-256-GCM");
    }

    std::vector<unsigned char> plaintext(ciphertext_len);
    int len, plaintext_len;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt master key");
    }
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set GCM tag");
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize master key decryption");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}