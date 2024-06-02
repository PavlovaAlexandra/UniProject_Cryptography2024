#ifndef HASHING_H
#define HASHING_H

#include <iostream>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>

std::string byteArrayToHexString(const unsigned char* byteArray, size_t length);

std::string generate_salt(size_t length);

std::string sha256(const std::string& input);

std::string hash_password(const std::string& password, const std::string& salt);

bool verify_password(const std::string& password, const std::string& salt, const std::string& hash);

#endif // HASHING_H
