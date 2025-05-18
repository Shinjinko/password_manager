#include "../h/crypto.h"
#include <fstream>
#include <stdexcept>
#include <openssl/sha.h>
#include <openssl/err.h>
#include "../h/mmap_utils.h"

// Constructor: initialize Crypto object with password and key file
Crypto::Crypto(const std::string& password, const std::string& key_file) : key_file(key_file), ctx(nullptr) {
    initializeContext();
    loadOrGenerateMasterKey(password);
}

// Destructor: clean up OpenSSL context
Crypto::~Crypto() {
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = nullptr;
    }
}

// Initialize OpenSSL cipher context
void Crypto::initializeContext() {
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP context");
    }
}

// Load master key from file or generate a new one
void Crypto::loadOrGenerateMasterKey(const std::string& password) {
    // Check if key file exists
    if (std::ifstream(key_file)) {
        // Load and decrypt master key
        master_key = MMAPUtils::loadMasterKey(key_file, password);
    } else {
        // Generate new master key (32 bytes for AES-256)
        master_key.resize(32);
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&master_key[0]), 32) != 1) {
            throw std::runtime_error("Failed to generate master key");
        }
        // Store master key in file
        MMAPUtils::storeMasterKey(key_file, master_key, password);
    }
}

// Static method to hash password using SHA-256
std::string Crypto::hashPassword(const std::string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password.c_str(), password.size());
    SHA256_Final(hash, &sha256);

    // Convert hash to hexadecimal string
    char hex[2 * SHA256_DIGEST_LENGTH + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex + 2 * i, "%02x", hash[i]);
    }
    hex[2 * SHA256_DIGEST_LENGTH] = '\0';
    return std::string(hex);
}

// Encrypt plaintext using AES-256-GCM
std::string Crypto::encrypt(const std::string& plaintext) {
    if (plaintext.empty()) return "";

    unsigned char iv[12];
    if (RAND_bytes(iv, 12) != 1) {
        throw std::runtime_error("Failed to generate IV");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, reinterpret_cast<const unsigned char*>(master_key.c_str()), iv) != 1) {
        throw std::runtime_error("Failed to initialize encryption");
    }

    std::string ciphertext;
    ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len, ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size()) != 1) {
        throw std::runtime_error("Failed to encrypt data");
    }
    ciphertext_len += len;

    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[ciphertext_len]), &len) != 1) {
        throw std::runtime_error("Failed to finalize encryption");
    }
    ciphertext_len += len;

    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        throw std::runtime_error("Failed to get GCM tag");
    }

    // Append IV and tag to ciphertext
    std::string result = std::string(reinterpret_cast<char*>(iv), 12) + ciphertext.substr(0, ciphertext_len) + std::string(reinterpret_cast<char*>(tag), 16);
    return result;
}

// Decrypt ciphertext using AES-256-GCM
std::string Crypto::decrypt(const std::string& ciphertext) {
    if (ciphertext.size() < 28) return ""; // Minimum size: 12 (IV) + 16 (tag)

    // Extract IV, ciphertext, and tag
    std::string iv = ciphertext.substr(0, 12);
    std::string tag = ciphertext.substr(ciphertext.size() - 16);
    std::string data = ciphertext.substr(12, ciphertext.size() - 28);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, reinterpret_cast<const unsigned char*>(master_key.c_str()),
                           reinterpret_cast<const unsigned char*>(iv.c_str())) != 1) {
        throw std::runtime_error("Failed to initialize decryption");
    }

    std::string plaintext;
    plaintext.resize(data.size() + EVP_MAX_BLOCK_LENGTH);
    int len, plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &len,
                          reinterpret_cast<const unsigned char*>(data.c_str()), data.size()) != 1) {
        throw std::runtime_error("Failed to decrypt data");
    }
    plaintext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<char*>(tag.c_str())) != 1) {
        throw std::runtime_error("Failed to set GCM tag");
    }

    if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plaintext[plaintext_len]), &len) != 1) {
        throw std::runtime_error("Failed to finalize decryption");
    }
    plaintext_len += len;

    return plaintext.substr(0, plaintext_len);
}