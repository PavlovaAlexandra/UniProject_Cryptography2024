#include "crypto.h"
#include <random>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/pem.h>

std::string byteArrayToHexString(const unsigned char* byteArray, size_t length) { //convert the string into an hexadecimal

    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byteArray[i]; //convert step-by-step adding a padding if necessary
    }
    return oss.str();
}

std::string Crypto::generateSalt(size_t length) {

    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::default_random_engine rng(std::random_device{}());
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);
    std::string salt;

    for (size_t i = 0; i < length; ++i) {
        salt += charset[dist(rng)];
    }
    return salt;
}

// Funzione per hashare una password utilizzando SHA-256
// byte array of a certain lenght and then we calculate the hashing 
std::string Crypto::sha256(const std::string& input) {

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    const EVP_MD* md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    if (1 != EVP_DigestInit_ex(mdctx, md, nullptr)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }
    if (1 != EVP_DigestUpdate(mdctx, input.c_str(), input.size())) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &lengthOfHash)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(mdctx);

    return byteArrayToHexString(hash, lengthOfHash);
}

std::string Crypto::hashPassword(const std::string& password, const std::string& salt) {
    return sha256(password + salt);
}

// Funzione per verificare la password
bool Crypto::verifyPassword(const std::string& password, const std::string& salt, const std::string& hash) {
    return hash == hashPassword(password, salt);
}

std::pair<std::string, std::string> Crypto::generateDiffieHellmanKeys() { //this fuction is temporary and not official, so do not use it: 
                                                                          //I wanted to create DH keys, but maybe we can do a better job with slides
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr);
    if (ctx == nullptr) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    if (1 != EVP_PKEY_keygen_init(ctx)) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen_init failed");
    }

    if (1 != EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, 2048)) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_CTX_set_dh_paramgen_prime_len failed");
    }

    EVP_PKEY* params = nullptr;
    if (1 != EVP_PKEY_keygen(ctx, &params)) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen failed");
    }

    EVP_PKEY_CTX_free(ctx);

    EVP_PKEY_CTX* ctx2 = EVP_PKEY_CTX_new(params, nullptr);
    if (ctx2 == nullptr) {
        EVP_PKEY_free(params);
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    if (1 != EVP_PKEY_keygen_init(ctx2)) {
        EVP_PKEY_CTX_free(ctx2);
        EVP_PKEY_free(params);
        throw std::runtime_error("EVP_PKEY_keygen_init failed");
    }

    EVP_PKEY* key1 = nullptr;
    if (1 != EVP_PKEY_keygen(ctx2, &key1)) {
        EVP_PKEY_CTX_free(ctx2);
        EVP_PKEY_free(params);
        throw std::runtime_error("EVP_PKEY_keygen failed");
    }

    EVP_PKEY* key2 = nullptr;
    if (1 != EVP_PKEY_keygen(ctx2, &key2)) {
        EVP_PKEY_CTX_free(ctx2);
        EVP_PKEY_free(params);
        EVP_PKEY_free(key1);
        throw std::runtime_error("EVP_PKEY_keygen failed");
    }

    EVP_PKEY_CTX_free(ctx2);

    // Convert keys to strings
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
        EVP_PKEY_free(params);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        throw std::runtime_error("Failed to create BIO");
    }

    if (1 != PEM_write_bio_PUBKEY(bio, key1)) {
        BIO_free(bio);
        EVP_PKEY_free(params);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        throw std::runtime_error("PEM_write_bio_PUBKEY failed");
    }

    char* key1Str = nullptr;
    long key1Len = BIO_get_mem_data(bio, &key1Str);
    std::string publicKey1(key1Str, key1Len);

    BIO_reset(bio);

    if (1 != PEM_write_bio_PUBKEY(bio, key2)) {
        BIO_free(bio);
        EVP_PKEY_free(params);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        throw std::runtime_error("PEM_write_bio_PUBKEY failed");
    }

    char* key2Str = nullptr;
    long key2Len = BIO_get_mem_data(bio, &key2Str);
    std::string publicKey2(key2Str, key2Len);

    BIO_free(bio);
    EVP_PKEY_free(params);
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);

    return std::make_pair(publicKey1, publicKey2);
}