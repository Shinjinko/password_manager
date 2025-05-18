#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Class for handling cryptographic operations
class Crypto {
private:
    std::string master_key; // Master key for encryption
    std::string key_file;   // Path to the key file
    EVP_CIPHER_CTX* ctx;    // OpenSSL encryption context

    // Initialize the OpenSSL cipher context
    void initializeContext();
    // Load existing master key or generate a new one
    void loadOrGenerateMasterKey(const std::string& password);

public:
    // Constructor: initialize with user password and key file path
    Crypto(const std::string& password, const std::string& key_file);
    // Destructor: clean up OpenSSL context
    ~Crypto();

    // Static method to hash a password using SHA-256
    static std::string hashPassword(const std::string& password);
    // Encrypt plaintext using AES-256-GCM
    std::string encrypt(const std::string& plaintext);
    // Decrypt ciphertext using AES-256-GCM
    std::string decrypt(const std::string& ciphertext);
};

#endif // CRYPTO_H