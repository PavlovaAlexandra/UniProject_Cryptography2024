#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>

#include "encryptionAES.h"
#include "RSA_utils.h"
#include "hashing.h"

// Отправка сообщения серверу
bool sendMessageToServer(int client_sock, const std::string &message)
{
    if (send(client_sock, message.c_str(), message.length(), 0) == -1)
    {
        std::cerr << "Send failed: " << strerror(errno) << std::endl;
        return false;
    }
    return true;
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
    int client_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sock == -1)
    {
        std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
        return -1;
    }

    // Настройка адреса сервера и порта
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(12345);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Подключение к серверу
    if (connect(client_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        std::cerr << "Connect failed: " << strerror(errno) << std::endl;
        close(client_sock);
        return -1;
    }

    std::cout << "Connected to server" << std::endl;

    // Получение публичного ключа сервера
    char buffer[4096];
    int len = read(client_sock, buffer, sizeof(buffer) - 1);
    if (len == -1)
    {
        std::cerr << "Read failed: " << strerror(errno) << std::endl;
        close(client_sock);
        return -1;
    }
    buffer[len] = '\0';
    std::string server_pub_key_str(buffer);

    BIO *bio = BIO_new_mem_buf((void *)server_pub_key_str.c_str(), -1);
    RSA *server_rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!server_rsa)
    {
        std::cerr << "Failed to parse server public key" << std::endl;
        close(client_sock);
        return -1;
    }

    std::cout << "Server public key received:" << std::endl;
    printRSAKey(server_rsa, false);

    // Генерация случайного числа R
    std::string R = generateRandomNumber();
    std::cout << "Random number R generated: " << R << std::endl;

    // Отправка случайного числа R серверу
    if (send(client_sock, R.c_str(), R.length(), 0) == -1)
    {
        std::cerr << "Send failed: " << strerror(errno) << std::endl;
        close(client_sock);
        RSA_free(server_rsa);
        return -1;
    }

    // Получение сертификата и временного публичного ключа от сервера
    uint32_t cert_len;
    len = read(client_sock, &cert_len, sizeof(cert_len));
    if (len == -1)
    {
        std::cerr << "Read failed: " << strerror(errno) << std::endl;
        close(client_sock);
        RSA_free(server_rsa);
        return -1;
    }
    cert_len = ntohl(cert_len);

    std::string cert;
    cert.resize(cert_len);
    len = read(client_sock, &cert[0], cert_len);
    if (len == -1)
    {
        std::cerr << "Read failed: " << strerror(errno) << std::endl;
        close(client_sock);
        RSA_free(server_rsa);
        return -1;
    }

    uint32_t sig_len;
    len = read(client_sock, &sig_len, sizeof(sig_len));
    if (len == -1)
    {
        std::cerr << "Read failed: " << strerror(errno) << std::endl;
        close(client_sock);
        RSA_free(server_rsa);
        return -1;
    }
    sig_len = ntohl(sig_len);

    std::string signature;
    signature.resize(sig_len);
    len = read(client_sock, &signature[0], sig_len);
    if (len == -1)
    {
        std::cerr << "Read failed: " << strerror(errno) << std::endl;
        close(client_sock);
        RSA_free(server_rsa);
        return -1;
    }

    // Извлечение временного публичного ключа из сертификата
    std::string temp_pub_key_str = cert.substr(R.length());

    bio = BIO_new_mem_buf((void *)temp_pub_key_str.c_str(), -1);
    RSA *temp_rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!temp_rsa)
    {
        std::cerr << "Failed to parse temporary public key" << std::endl;
        close(client_sock);
        RSA_free(server_rsa);
        return -1;
    }

    std::cout << "Temporary public key received:" << std::endl;
    printRSAKey(temp_rsa, false);

    // Проверка сертификата
    if (!verifySignature(server_rsa, cert, signature))
    {
        std::cerr << "Certificate verification failed" << std::endl;
        close(client_sock);
        RSA_free(server_rsa);
        RSA_free(temp_rsa);
        return -1;
    }

    std::cout << "Certificate verified successfully" << std::endl;

    // Генерация сессионного ключа
    std::string session_key = generateRandomNumber();
    std::cout << "Session key generated: " << stringToHex(session_key) << std::endl;

    // Шифрование сессионного ключа временным публичным ключом
    unsigned char *encrypted_session_key = new unsigned char[RSA_size(temp_rsa)];
    int encrypted_session_key_len = RSA_public_encrypt(session_key.length(), (unsigned char *)session_key.c_str(), encrypted_session_key, temp_rsa, RSA_PKCS1_OAEP_PADDING);

    if (encrypted_session_key_len == -1)
    {
        std::cerr << "Session key encryption failed" << std::endl;
        delete[] encrypted_session_key;
        close(client_sock);
        RSA_free(server_rsa);
        RSA_free(temp_rsa);
        return -1;
    }

    // Отправка зашифрованного сессионного ключа серверу
    std::string encrypted_session_key_str((char *)encrypted_session_key, encrypted_session_key_len);
    if (send(client_sock, encrypted_session_key_str.c_str(), encrypted_session_key_str.length(), 0) == -1)
    {
        std::cerr << "Send failed: " << strerror(errno) << std::endl;
        delete[] encrypted_session_key;
        close(client_sock);
        RSA_free(server_rsa);
        RSA_free(temp_rsa);
        return -1;
    }

    std::cout << "Encrypted session key sent to server" << std::endl;

    std::cout << std::endl;
    std::cout << "===========================================================" << std::endl;
    std::cout << "=============  SECURE CONNECTION ESTABLISHED  =============" << std::endl;
    std::cout << "=============      SESSION KEY GENERATED      =============" << std::endl;
    std::cout << "===========================================================" << std::endl;
    std::cout << std::endl;

    while (true)
    {
        std::cout << "Enter 'register', 'login', or 'exit': ";
        std::string message;
        std::cin >> message;

        std::string iv = "0123456789012345"; // Initialization Vector (IV)
        std::string encrypted_message;

        if (!aes_encrypt(message, encrypted_message, session_key, iv))
        {
            std::cerr << "Encryption failed" << std::endl;
            continue;
        }

        if (!sendMessageToServer(client_sock, encrypted_message))
        {
            close(client_sock);
            RSA_free(server_rsa);
            RSA_free(temp_rsa);
            return -1;
        }

        if (message == "exit")
        {
            break; // Завершаем цикл
        }
        else if (message == "register")
        {
            // Запрос информации у пользователя
            std::string email, nickname, password;
            std::cout << "Enter your email: ";
            std::cin >> email;
            std::cout << "Enter your nickname: ";
            std::cin >> nickname;
            std::cout << "Enter your password: ";
            std::cin >> password;

            // Генерация соли
            std::string salt = generate_salt(16);

            // Хеширование пароля с солью
            std::string hashed_password = hash_password(password, salt);

            // Формирование строки для отправки: email;nickname;hashed_password;salt
            std::string registration_info = email + ";" + nickname + ";" + hashed_password + ";" + salt;

            if (!aes_encrypt(registration_info, encrypted_message, session_key, iv))
            {
                std::cerr << "Encryption failed" << std::endl;
                continue;
            }

            if (!sendMessageToServer(client_sock, encrypted_message))
            {
                close(client_sock);
                RSA_free(server_rsa);
                RSA_free(temp_rsa);
                return -1;
            }
            
            // Получить ответ от сервера
            std::string response;
            uint32_t response_len;
            if (recv(client_sock, &response_len, sizeof(response_len), 0) == -1)
            {
                std::cerr << "Receive failed: " << strerror(errno) << std::endl;
                close(client_sock);
                RSA_free(server_rsa);
                RSA_free(temp_rsa);
                return -1;
            }
            response_len = ntohl(response_len);

            char *buffer = new char[response_len + 1];
            if (recv(client_sock, buffer, response_len, 0) == -1)
            {
                std::cerr << "Receive failed: " << strerror(errno) << std::endl;
                delete[] buffer;
                close(client_sock);
                RSA_free(server_rsa);
                RSA_free(temp_rsa);
                return -1;
            }
            buffer[response_len] = '\0';
            response = std::string(buffer);
            delete[] buffer;

            // Вывести сообщение пользователю
            std::cout << response << std::endl;
        }
        else if (message == "login")
        {
            // Запрос информации у пользователя
            std::string nickname, password;
            std::cout << "Enter your nickname: ";
            std::cin >> nickname;
            std::cout << "Enter your password: ";
            std::cin >> password;

            // Отправка информации на сервер
            std::string login_info = nickname + ";" + password;
            if (!aes_encrypt(login_info, encrypted_message, session_key, iv))
            {
                std::cerr << "Encryption failed" << std::endl;
                continue;
            }

            if (!sendMessageToServer(client_sock, encrypted_message))
            {
                close(client_sock);
                RSA_free(server_rsa);
                RSA_free(temp_rsa);
                return -1;
            }

            // Получить ответ от сервера
            std::string response;
            uint32_t response_len;
            if (recv(client_sock, &response_len, sizeof(response_len), 0) == -1)
            {
                std::cerr << "Receive failed: " << strerror(errno) << std::endl;
                close(client_sock);
                RSA_free(server_rsa);
                RSA_free(temp_rsa);
                return -1;
            }
            response_len = ntohl(response_len);

            char *buffer = new char[response_len + 1];
            if (recv(client_sock, buffer, response_len, 0) == -1)
            {
                std::cerr << "Receive failed: " << strerror(errno) << std::endl;
                delete[] buffer;
                close(client_sock);
                RSA_free(server_rsa);
                RSA_free(temp_rsa);
                return -1;
            }
            buffer[response_len] = '\0';
            response = std::string(buffer);
            delete[] buffer;

            // Расшифровать ответ от сервера
            std::string decrypted_response;
            if (!aes_decrypt(response, decrypted_response, session_key, iv))
            {
                std::cerr << "Decryption of server response failed" << std::endl;
                close(client_sock);
                RSA_free(server_rsa);
                RSA_free(temp_rsa);
                return -1;
            }

            // Вывести расшифрованное сообщение пользователю
            std::cout << decrypted_response << std::endl;

            // Проверка успешности входа
            if (decrypted_response.find("Login successful") != std::string::npos)
            {
                while (true)
                {
                    std::cout << "Enter 'List', 'Get', 'Add', or 'logout': ";
                    std::string command;
                    std::cin >> command;

                    if (command == "logout")
                    {
                        break;
                    }
                    else if (command == "List")
                    {
                        std::string n;
                        std::cout << "Enter number of messages to list: ";
                        std::cin >> n;
                        command += " " + n;
                    }
                    else if (command == "Get")
                    {
                        std::string mid;
                        std::cout << "Enter message identifier: ";
                        std::cin >> mid;
                        command += " " + mid;
                    }
                    else if (command == "Add")
                    {
                        std::string title, author, body;
                        std::cout << "Enter message title: ";
                        std::cin.ignore(); // Ignore newline character left in buffer
                        std::getline(std::cin, title);
                        std::cout << "Enter message author: ";
                        std::getline(std::cin, author);
                        std::cout << "Enter message body: ";
                        std::getline(std::cin, body);
                        command += " " + title + ";" + author + ";" + body;
                    }
                    else
                    {
                        std::cout << "Invalid command." << std::endl;
                        continue;
                    }

                    // Шифруем команду
                    if (!aes_encrypt(command, encrypted_message, session_key, iv))
                    {
                        std::cerr << "Encryption failed" << std::endl;
                        continue;
                    }

                    // Отправляем команду на сервер
                    if (!sendMessageToServer(client_sock, encrypted_message))
                    {
                        close(client_sock);
                        RSA_free(server_rsa);
                        RSA_free(temp_rsa);
                        return -1;
                    }

                    // Получаем ответ от сервера
                    if (recv(client_sock, &response_len, sizeof(response_len), 0) == -1)
                    {
                        std::cerr << "Receive failed: " << strerror(errno) << std::endl;
                        close(client_sock);
                        RSA_free(server_rsa);
                        RSA_free(temp_rsa);
                        return -1;
                    }
                    response_len = ntohl(response_len);

                    buffer = new char[response_len + 1];
                    if (recv(client_sock, buffer, response_len, 0) == -1)
                    {
                        std::cerr << "Receive failed: " << strerror(errno) << std::endl;
                        delete[] buffer;
                        close(client_sock);
                        RSA_free(server_rsa);
                        RSA_free(temp_rsa);
                        return -1;
                    }
                    buffer[response_len] = '\0';
                    response = std::string(buffer);
                    delete[] buffer;

                    // // Расшифровываем ответ
                    // if (!aes_decrypt(response, decrypted_response, session_key, iv))
                    // {
                    //     std::cerr << "Decryption failed" << std::endl;
                    //     continue;
                    // }

                    // Выводим результат
                    std::cout << response << std::endl;
                }
            }
        }
        else
        {
            std::cout << "Invalid command. Please enter 'register', 'login', or 'exit'." << std::endl;
        }
    }

    // Очистка ресурсов
    delete[] encrypted_session_key;
    close(client_sock);
    RSA_free(server_rsa);
    RSA_free(temp_rsa);

    return 0;
}