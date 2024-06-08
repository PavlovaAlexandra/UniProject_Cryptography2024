#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <sqlite3.h>
#include <sstream>
#include <vector>

#include "encryptionAES.h"
#include "RSA_utils.h"
#include "hashing.h"

// Функция для выполнения запросов к базе данных
int executeQuery(sqlite3 *db, const std::string &query)
{
    char *errMsg;
    int result = sqlite3_exec(db, query.c_str(), NULL, 0, &errMsg);
    if (result != SQLITE_OK)
    {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }
    return result;
}

int executeQueryWithResult(sqlite3 *db, const std::string &query, int &result_count)
{
    sqlite3_stmt *stmt;
    int result = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);
    if (result != SQLITE_OK)
    {
        std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
        return result;
    }

    // Выполнение запроса
    result = sqlite3_step(stmt);
    if (result != SQLITE_ROW && result != SQLITE_DONE)
    {
        std::cerr << "SQL execution error: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return result;
    }

    // Получение результата
    if (result == SQLITE_ROW)
    {
        // Результат есть, извлекаем его
        result_count = sqlite3_column_int(stmt, 0);
    }
    else if (result == SQLITE_DONE)
    {
        // Результат пуст
        result_count = 0;
    }

    // Освобождаем выделенные ресурсы
    sqlite3_finalize(stmt);

    return SQLITE_OK;
}

int executeQueryWithResult(sqlite3* db, const std::string& query, std::string& result)
{
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
    {
        std::cerr << "SQL error (prepare): " << sqlite3_errmsg(db) << std::endl;
        return rc;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
    {
        const unsigned char* text = sqlite3_column_text(stmt, 0);
        if (text)
        {
            result = reinterpret_cast<const char*>(text);
        }
        else
        {
            result.clear();
        }
        rc = SQLITE_OK; // Данные извлечены успешно
    }
    else if (rc == SQLITE_DONE)
    {
        result.clear();
        std::cerr << "No rows found for query: " << query << std::endl;
        rc = SQLITE_ERROR; // Нет строк, считаем это ошибкой для данной функции
    }
    else
    {
        std::cerr << "SQL error (step): " << sqlite3_errmsg(db) << std::endl;
    }

    sqlite3_finalize(stmt);
    return rc;
}


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

    // Инициализация SQLite и открытие базы данных
    sqlite3 *db;
    int rc = sqlite3_open("BBS.db", &db);
    if (rc)
    {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return -1;
    }

    // Создание таблицы пользователей (если не существует)
    std::string createTableQuery = "CREATE TABLE IF NOT EXISTS users (email TEXT, nickname TEXT, password TEXT, salt TEXT);";
    rc = executeQuery(db, createTableQuery);
    if (rc != SQLITE_OK)
    {
        std::cerr << "Failed to create table: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return -1;
    }

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
            sqlite3_close(db);
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
        else if (decrypted_message == "register")
        {
            // Получить зашифрованные данные о регистрации от клиента
            encrypted_message = receiveMessageFromClient(client_sock);
            if (encrypted_message.empty())
            {
                close(client_sock);
                close(server_sock);
                RSA_free(rsa);
                RSA_free(temp_rsa);
                sqlite3_close(db);
                return -1;
            }

            // Расшифровать полученное сообщение
            if (!aes_decrypt(encrypted_message, decrypted_message, session_key, iv))
            {
                std::cerr << "Decryption failed" << std::endl;
                continue;
            }

            std::cout << "Received user info from client: " << decrypted_message << std::endl;

            // Разбить полученную информацию на компоненты с разделителем ";"
            std::istringstream iss(decrypted_message);
            std::vector<std::string> components;
            std::string component;
            while (std::getline(iss, component, ';'))
            {
                components.push_back(component);
            }

            // Проверка, что количество компонентов соответствует ожидаемому
            if (components.size() != 4)
            {
                std::cerr << "Invalid user info format" << std::endl;
                continue; // Можно обработать ошибку каким-то образом и продолжить цикл
            }

            // Извлечение компонентов из вектора
            std::string email = components[0];
            std::string nickname = components[1];
            std::string password = components[2];
            std::string salt = components[3];

            ///////////////////////////////////
            /////до этого момента все хорошо, разбили полученные данные на email, nickname, password и соль

            // Проверка уникальности логина в базе данных
            std::string checkQuery = "SELECT COUNT(*) FROM users WHERE nickname='" + nickname + "';";
            int count;
            rc = executeQueryWithResult(db, checkQuery, count);
            //////////
            std::cout << "rc: " << rc << std::endl;
            ////////
            if (rc != SQLITE_OK)
            {
                std::cerr << "Failed to execute query to check nickname existence" << std::endl;
                continue; // Можно обработать ошибку и продолжить цикл
            }
            if (count > 0)
            {
                ////////////
                std::cout << "Логин уже есть!" << std::endl;
                ////////////

                // Логин уже существует, отправить клиенту сообщение об ошибке
                std::string error_message = "Nickname already exists. Please choose a different nickname.";
                uint32_t msg_len = htonl(error_message.length());
                if (send(client_sock, &msg_len, sizeof(msg_len), 0) == -1)
                {
                    std::cerr << "Send failed: " << strerror(errno) << std::endl;
                    close(client_sock);
                    close(server_sock);
                    RSA_free(rsa);
                    RSA_free(temp_rsa);
                    sqlite3_close(db);
                    return -1;
                }

                if (send(client_sock, error_message.c_str(), error_message.length(), 0) == -1)
                {
                    std::cerr << "Send failed: " << strerror(errno) << std::endl;
                    close(client_sock);
                    close(server_sock);
                    RSA_free(rsa);
                    RSA_free(temp_rsa);
                    sqlite3_close(db);
                    return -1;
                }
                std::cout << "Сообщение о том что такой логин уже есть отправлено" << std::endl;
                continue; // Прервать регистрацию
            }

            // Запись информации о пользователе в базу данных
            std::string insertQuery = "INSERT INTO users (email, nickname, password, salt) VALUES ('" + email + "', '" + nickname + "', '" + password + "', '" + salt + "');";
            rc = executeQuery(db, insertQuery);
            if (rc != SQLITE_OK)
            {
                std::cerr << "Failed to insert user info into database" << std::endl;
                std::string error_message = "Registration failed. Please try again.";
                uint32_t msg_len = htonl(error_message.length());
                if (send(client_sock, &msg_len, sizeof(msg_len), 0) == -1)
                {
                    std::cerr << "Send failed: " << strerror(errno) << std::endl;
                    close(client_sock);
                    close(server_sock);
                    RSA_free(rsa);
                    RSA_free(temp_rsa);
                    sqlite3_close(db);
                    return -1;
                }

                if (send(client_sock, error_message.c_str(), error_message.length(), 0) == -1)
                {
                    std::cerr << "Send failed: " << strerror(errno) << std::endl;
                    close(client_sock);
                    close(server_sock);
                    RSA_free(rsa);
                    RSA_free(temp_rsa);
                    sqlite3_close(db);
                    return -1;
                }
                continue; // Можно обработать ошибку каким-то образом и продолжить цикл
            }
            std::cout << "User info inserted into database" << std::endl;

            // Отправка сообщения об успешной регистрации
            std::string success_message = "Registration successful. You can log in now, " + nickname + "!";
            uint32_t msg_len = htonl(success_message.length());
            if (send(client_sock, &msg_len, sizeof(msg_len), 0) == -1)
            {
                std::cerr << "Send failed: " << strerror(errno) << std::endl;
                close(client_sock);
                close(server_sock);
                RSA_free(rsa);
                RSA_free(temp_rsa);
                sqlite3_close(db);
                return -1;
            }

            if (send(client_sock, success_message.c_str(), success_message.length(), 0) == -1)
            {
                std::cerr << "Send failed: " << strerror(errno) << std::endl;
                close(client_sock);
                close(server_sock);
                RSA_free(rsa);
                RSA_free(temp_rsa);
                sqlite3_close(db);
                return -1;
            }
            std::cout << "Message sent to client about successful registration in database" << std::endl;
        }
        else if (decrypted_message == "login")
        {
            // Обработка регистрации или входа
            encrypted_message = receiveMessageFromClient(client_sock);
            if (encrypted_message.empty())
            {
                close(client_sock);
                close(server_sock);
                RSA_free(rsa);
                RSA_free(temp_rsa);
                sqlite3_close(db);
                return -1;
            }

            if (!aes_decrypt(encrypted_message, decrypted_message, session_key, iv))
            {
                std::cerr << "Decryption failed" << std::endl;
                continue;
            }

            std::cout << "Received user info from client: " << decrypted_message << std::endl;

            // Разбиение строки decrypted_message на компоненты с разделителем ";"
            std::istringstream iss(decrypted_message);
            std::vector<std::string> components;
            std::string component;
            while (std::getline(iss, component, ';'))
            {
                components.push_back(component);
            }

            // Проверка, что количество компонентов соответствует ожидаемому
            if (components.size() != 2)
            {
                std::cerr << "Invalid user info format" << std::endl;
                continue; // Можно обработать ошибку каким-то образом и продолжить цикл
            }

            // Извлечение компонентов из вектора
            std::string nickname = components[0];
            std::string password = components[1];

            ////////////
            std::cout << "Nickname: " << nickname << std::endl;
            std::cout << "Password: " << password << std::endl;
            ////////////

            // Получить соль из базы данных
            std::string db_salt;
            std::string selectSaltQuery = "SELECT salt FROM users WHERE nickname='" + nickname + "';";
            int rc1 = executeQueryWithResult(db, selectSaltQuery, db_salt);
            std::cout << "rc1= " << rc1 << std::endl;
            if (rc1 != SQLITE_OK || db_salt.empty())
            {
                std::cerr << "Failed to retrieve salt from database or no salt found for user: " << nickname << std::endl;
                std::string error_message = "Invalid login or password. Please try again.";
                std::string encrypted_response;
                if (!aes_encrypt(error_message, encrypted_response, session_key, iv))
                {
                    std::cerr << "Encryption failed" << std::endl;
                    continue;
                }

                uint32_t msg_len = htonl(encrypted_response.length());
                send(client_sock, &msg_len, sizeof(msg_len), 0);
                send(client_sock, encrypted_response.c_str(), encrypted_response.length(), 0);
                continue;
            }

            // Хеширование введенного пароля с солью
            std::string hashed_password = hash_password(password, db_salt);

            // Получить хэш пароля из базы данных
            std::string db_hashed_password;
            std::string selectPasswordQuery = "SELECT password FROM users WHERE nickname='" + nickname + "';";
            int rc2 = executeQueryWithResult(db, selectPasswordQuery, db_hashed_password);
            if (rc2 != SQLITE_OK)
            {
                std::cerr << "Failed to retrieve hashed password from database" << std::endl;
                continue;
            }

            // Сравнить хэши
            if (hashed_password == db_hashed_password)
            {
                std::string success_message = "Login successful. Welcome, " + nickname + "!";
                std::string encrypted_response;
                if (!aes_encrypt(success_message, encrypted_response, session_key, iv))
                {
                    std::cerr << "Encryption failed" << std::endl;
                    continue;
                }

                uint32_t msg_len = htonl(encrypted_response.length());
                send(client_sock, &msg_len, sizeof(msg_len), 0);
                send(client_sock, encrypted_response.c_str(), encrypted_response.length(), 0);
            }
            else
            {
                std::string error_message = "Invalid login or password. Please try again.";
                std::string encrypted_response;
                if (!aes_encrypt(error_message, encrypted_response, session_key, iv))
                {
                    std::cerr << "Encryption failed" << std::endl;
                    continue;
                }

                uint32_t msg_len = htonl(encrypted_response.length());
                send(client_sock, &msg_len, sizeof(msg_len), 0);
                send(client_sock, encrypted_response.c_str(), encrypted_response.length(), 0);
            }
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
    sqlite3_close(db);

    return 0;
}