#ifndef MMAP_UTILS_H
#define MMAP_UTILS_H

#include <string>
#include <vector>

struct TOTPCacheEntry {
    int user_id;
    char code[7]; // 6 цифр + '\0'
    time_t timestamp;
};

class MMAPUtils {
public:
    // Кэш TOTP-кодов
    static void initTOTPCache(const std::string& cache_file, size_t max_entries);
    static bool addTOTPCacheEntry(const std::string& cache_file, int user_id, const std::string& code);
    static bool isCodeInCache(const std::string& cache_file, int user_id, const std::string& code);
    static void cleanupTOTPCache(const std::string& cache_file);

    // Буфер импорта/экспорта
    static void writeImportExportBuffer(const std::string& buffer_file, const std::string& data);
    static std::string readImportExportBuffer(const std::string& buffer_file);

    // Мастер-ключ
    static void storeMasterKey(const std::string& key_file, const std::string& key, const std::string& encryption_key);
    static std::string loadMasterKey(const std::string& key_file, const std::string& encryption_key);
};

#endif // MMAP_UTILS_H