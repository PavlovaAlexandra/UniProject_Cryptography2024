#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>

// Объявление функций шифрования и расшифровки
bool aes_encrypt(const std::string &plain_text, std::string &encrypted_text, const std::string &key, std::string &iv);
bool aes_decrypt(const std::string &encrypted_text, std::string &plain_text, const std::string &key, const std::string &iv);

#endif // ENCRYPTION_H
