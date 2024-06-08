#ifndef RSA_UTILS_H
#define RSA_UTILS_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string>

// Функция для вывода RSA ключей в PEM формате
void printRSAKey(RSA *rsa, bool isPrivate);

// Подпись сообщения приватным ключом RSA
std::string signMessage(RSA *rsa, const std::string &message);

// Проверка подписи сообщения с использованием публичного ключа RSA
bool verifySignature(RSA *rsa, const std::string &message, const std::string &signature);

#endif // RSA_UTILS_H
