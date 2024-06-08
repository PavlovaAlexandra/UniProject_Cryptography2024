#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

#include "encryptionAES.h"

// Получение сообщения от клиента
std::string receiveMessageFromClient(int client_sock)
{
    char buffer[4096];
    int len = read(client_sock, buffer, sizeof(buffer) - 1);
    if (len == -1)
    {
        std::cerr << "Read failed: " << strerror(errno) << std::endl;
        return "";
    }
    buffer[len] = '\0';
    return std::string(buffer, len);
}

// Функция для вывода RSA ключей в PEM формате
void printRSAKey(RSA *rsa, bool isPrivate)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (isPrivate)
    {
        PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
    }
    else
    {
        PEM_write_bio_RSAPublicKey(bio, rsa);
    }
    char *key_data = NULL;
    long len = BIO_get_mem_data(bio, &key_data);
    std::string key_str(key_data, len);
    std::cout << key_str << std::endl;
    BIO_free(bio);
}

// Генерация случайного числа
std::string generateRandomNumber()
{
    unsigned char random_number[32];
    if (RAND_bytes(random_number, sizeof(random_number)) != 1)
    {
        std::cerr << "Failed to generate random number" << std::endl;
        return "";
    }
    return std::string((char *)random_number, sizeof(random_number));
}

// Подпись сообщения приватным ключом RSA
std::string signMessage(RSA *rsa, const std::string &message)
{
    unsigned char hash[32];
    unsigned int sig_len;
    unsigned char *sig = new unsigned char[RSA_size(rsa)];

    if (SHA256((unsigned char *)message.c_str(), message.length(), hash) == NULL)
    {
        std::cerr << "SHA256 calculation failed" << std::endl;
        delete[] sig;
        return "";
    }

    if (RSA_sign(NID_sha256, hash, sizeof(hash), sig, &sig_len, rsa) != 1)
    {
        std::cerr << "Signing failed" << std::endl;
        delete[] sig;
        return "";
    }

    std::string signature((char *)sig, sig_len);
    delete[] sig;
    return signature;
}

// Функция для конвертации строки в шестнадцатеричное представление
std::string stringToHex(const std::string &input)
{
    static const char *const lut = "0123456789ABCDEF";
    size_t len = input.length();

    std::string output;
    output.reserve(2 * len);

    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }

    return output;
}

int main()
{
    // Создание сокета
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == -1)
    {
        std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
        return -1;
    }

    // Настройка адреса сервера и порта
    struct sockaddr_in serv_addr, client_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(12345);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    // Привязка сокета
    if (bind(server_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        std::cerr << "Bind failed: " << strerror(errno) << std::endl;
        close(server_sock);
        return -1;
    }

    // Прослушивание входящих подключений
    if (listen(server_sock, 1) == -1)
    {
        std::cerr << "Listen failed: " << strerror(errno) << std::endl;
        close(server_sock);
        return -1;
    }

    socklen_t client_len = sizeof(client_addr);
    int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
    if (client_sock == -1)
    {
        std::cerr << "Accept failed: " << strerror(errno) << std::endl;
        close(server_sock);
        return -1;
    }

    std::cout << "Client connected" << std::endl;

    // Генерация пары RSA ключей для сервера
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (!rsa)
    {
        std::cerr << "RSA key generation failed" << std::endl;
        close(client_sock);
        close(server_sock);
        return -1;
    }

    std::cout << "Server RSA keys generated" << std::endl;
    std::cout << "Public key:" << std::endl;
    printRSAKey(rsa, false);
    std::cout << "Private key:" << std::endl;
    printRSAKey(rsa, true);

    // Отправка открытого ключа RSA клиенту
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, rsa);
    char *pub_key_data = NULL;
    long pub_key_len = BIO_get_mem_data(bio, &pub_key_data);
    std::string pub_key_str(pub_key_data, pub_key_len);
    BIO_free(bio);

    if (send(client_sock, pub_key_str.c_str(), pub_key_str.length(), 0) == -1)
    {
        std::cerr << "Send failed: " << strerror(errno) << std::endl;
        close(client_sock);
        close(server_sock);
        RSA_free(rsa);
        return -1;
    }

    std::cout << "Public key sent to client" << std::endl;

    // Получение случайного числа R от клиента
    char buffer[4096];
    int len = read(client_sock, buffer, sizeof(buffer) - 1);
    if (len == -1)
    {
        std::cerr << "Read failed: " << strerror(errno) << std::endl;
        close(client_sock);
        close(server_sock);
        RSA_free(rsa);
        return -1;
    }
    buffer[len] = '\0';
    std::string R(buffer, len);

    std::cout << "Random number R received from client: " << R << std::endl;

    // Генерация временной пары RSA ключей
    RSA *temp_rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (!temp_rsa)
    {
        std::cerr << "Temporary RSA key generation failed" << std::endl;
        close(client_sock);
        close(server_sock);
        RSA_free(rsa);
        return -1;
    }

    std::cout << "Temporary RSA keys generated" << std::endl;
    std::cout << "Temporary public key:" << std::endl;
    printRSAKey(temp_rsa, false);
    std::cout << "Temporary private key:" << std::endl;
    printRSAKey(temp_rsa, true);

    // Создание сертификата (R + публичный temporary ключ)
    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, temp_rsa);
    char *temp_pub_key_data = NULL;
    long temp_pub_key_len = BIO_get_mem_data(bio, &temp_pub_key_data);
    std::string temp_pub_key_str(temp_pub_key_data, temp_pub_key_len);
    BIO_free(bio);

    std::string cert = R + temp_pub_key_str;

    // Подпись сертификата
    std::string signature = signMessage(rsa, cert);
    if (signature.empty())
    {
        std::cerr << "Signature creation failed" << std::endl;
        close(client_sock);
        close(server_sock);
        RSA_free(rsa);
        RSA_free(temp_rsa);
        return -1;
    }

    std::cout << "Certificate signed" << std::endl;

    // Отправка сертификата и временного публичного ключа клиенту
    uint32_t cert_len = htonl(cert.length());
    if (send(client_sock, &cert_len, sizeof(cert_len), 0) == -1)
    {
        std::cerr << "Send failed: " << strerror(errno) << std::endl;
        close(client_sock);
        close(server_sock);
        RSA_free(rsa);
        RSA_free(temp_rsa);
        return -1;
    }

    if (send(client_sock, cert.c_str(), cert.length(), 0) == -1)
    {
        std::cerr << "Send failed: " << strerror(errno) << std::endl;
        close(client_sock);
        close(server_sock);
        RSA_free(rsa);
        RSA_free(temp_rsa);
        return -1;
    }

    uint32_t sig_len = htonl(signature.length());
    if (send(client_sock, &sig_len, sizeof(sig_len), 0) == -1)
    {
        std::cerr << "Send failed: " << strerror(errno) << std::endl;
        close(client_sock);
        close(server_sock);
        RSA_free(rsa);
        RSA_free(temp_rsa);
        return -1;
    }

    if (send(client_sock, signature.c_str(), signature.length(), 0) == -1)
    {
        std::cerr << "Send failed: " << strerror(errno) << std::endl;
        close(client_sock);
        close(server_sock);
        RSA_free(rsa);
        RSA_free(temp_rsa);
        return -1;
    }

    std::cout << "Certificate and temporary public key sent to client" << std::endl;

    // Получение зашифрованного сессионного ключа от клиента
    len = read(client_sock, buffer, sizeof(buffer) - 1);
    if (len == -1)
    {
        std::cerr << "Read failed: " << strerror(errno) << std::endl;
        close(client_sock);
        close(server_sock);
        RSA_free(rsa);
        RSA_free(temp_rsa);
        return -1;
    }
    buffer[len] = '\0';
    std::string encrypted_session_key(buffer, len);

    // Расшифровка сессионного ключа временным приватным ключом
    unsigned char *decrypted_session_key = new unsigned char[RSA_size(temp_rsa)];
    int decrypted_session_key_len = RSA_private_decrypt(encrypted_session_key.length(), (unsigned char *)encrypted_session_key.c_str(), decrypted_session_key, temp_rsa, RSA_PKCS1_OAEP_PADDING);

    if (decrypted_session_key_len == -1)
    {
        std::cerr << "Session key decryption failed" << std::endl;
        delete[] decrypted_session_key;
        close(client_sock);
        close(server_sock);
        RSA_free(rsa);
        RSA_free(temp_rsa);
        return -1;
    }

    std::string session_key((char *)decrypted_session_key, decrypted_session_key_len);
    delete[] decrypted_session_key;

    std::cout << "Session key decrypted successfully" << std::endl;
    std::cout << "Session key: " << stringToHex(session_key) << std::endl;

    std::cout << std::endl;
    std::cout << "===========================================================" << std::endl;
    std::cout << "=============  SECURE CONNECTION ESTABLISHED  =============" << std::endl;
    std::cout << "=============      SESSION KEY GENERATED      =============" << std::endl;
    std::cout << "===========================================================" << std::endl;
    std::cout << std::endl;

    // Получаем сообщения от клиента
    while (true)
    {
        std::string encrypted_message = receiveMessageFromClient(client_sock);
        if (encrypted_message.empty())
        {
            close(client_sock);
            close(server_sock);
            RSA_free(rsa);
            RSA_free(temp_rsa);
            return -1;
        }

        std::string iv = "0123456789012345"; // Initialization Vector (IV)
        std::string decrypted_message;

        if (!aes_decrypt(encrypted_message, decrypted_message, session_key, iv))
        {
            std::cerr << "Decryption failed" << std::endl;
            continue;
        }

        std::cout << "Received message from client: " << decrypted_message << std::endl;

        if (decrypted_message == "exit")
        {
            break; // Завершаем цикл
        }
        else if (decrypted_message == "register" || decrypted_message == "login")
        {
            // Обработка регистрации или входа
            encrypted_message = receiveMessageFromClient(client_sock);
            if (encrypted_message.empty())
            {
                close(client_sock);
                close(server_sock);
                RSA_free(rsa);
                RSA_free(temp_rsa);
                return -1;
            }

            if (!aes_decrypt(encrypted_message, decrypted_message, session_key, iv))
            {
                std::cerr << "Decryption failed" << std::endl;
                continue;
            }

            std::cout << "Received user info from client: " << decrypted_message << std::endl;
            // Здесь можно добавить логику обработки полученной информации
        }
        else
        {
            // Обработка других сообщений
        }
    }

    // Закрытие соединений и освобождение ресурсов
    close(client_sock);
    close(server_sock);
    RSA_free(rsa);
    RSA_free(temp_rsa);

    return 0;
}