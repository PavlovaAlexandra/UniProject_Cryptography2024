#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <string>

class Crypto {

public:
    //Diffie-Hellman protocol
    static std::pair<std::string, std::string> generateDiffieHellmanKeys();
    static std::string generateSharedSecret(const std::string& publicKey, const std::string& privateKey);
    
    // RSA encryption/decryption
    static std::string encryptRSA(const std::string& data, const std::string& publicKey);
    static std::string decryptRSA(const std::string& data, const std::string& privateKey);
    
    // Password hashing and verification
    static std::string generateSalt(size_t length);
    static std::string sha256(const std::string& input);
    static std::string hashPassword(const std::string& password, const std::string& salt);
    static bool verifyPassword(const std::string& password, const std::string& salt, const std::string& hash);
    
    // Digital signatures
    static std::string signMessage(const std::string& message, const std::string& privateKey);
    static bool verifySignature(const std::string& message, const std::string& signature, const std::string& publicKey);

    //MAC generation and verification
    static std::string generateMAC(const std::string& message, const std::string& key);
    static bool verifyMAC(const std::string& message, const std::string& key, const std::string& mac);

    //Nonce generation
    static std::string generateNonce(size_t lenght);
};

#endif