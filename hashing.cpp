#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <random>

std::string byteArrayToHexString(const unsigned char* byteArray, size_t length) { //convert the string into an hexadecimal
    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byteArray[i]; //convert step-by-step adding a padding if necessary
    }
    return oss.str();
}

std::string generate_salt(size_t length) {
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
std::string sha256(const std::string& input) {
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

std::string hash_password(const std::string& password, const std::string& salt) {
    return sha256(password + salt);
}

// Funzione per verificare la password
bool verify_password(const std::string& password, const std::string& salt, const std::string& hash) {
    return hash == hash_password(password, salt);
}
/*
int main() {

    std::string password = "secure passoword";
    std::string salt = generate_salt(8);
    std::string hashed_password = hash_password(password, salt);

    std::string input;

    // Output di un messaggio per richiedere l'input all'utente
    std::cout << "Inserisci qualcosa: ";

    // Utilizzo di >> per leggere una singola parola di input dall'utente
    getline(std::cin, input);

    std::cout << "Salt: " << salt << std::endl;
    std::cout << "Hashed Password: " << hashed_password << std::endl;

    std::string hashed_input = hash_password(input, salt);

    bool isMatch = verify_password(password, salt, hashed_input);
    std::cout << "Password match: " << (isMatch ? "Yes" : "No") << std::endl;

    return 0;
}
*/
