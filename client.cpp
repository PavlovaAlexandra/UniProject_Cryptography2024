#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "hashing.h"

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method = SSLv23_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void connect_to_server(SSL *ssl) {
    int server_fd = SSL_get_fd(ssl);

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(8080);

    if (inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported\n";
        exit(EXIT_FAILURE);
    }

    if (connect(server_fd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        std::cerr << "Connection failed\n";
        exit(EXIT_FAILURE);
    }

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    std::cout << "Connected to the server.\n";
}

void handle_response(SSL *ssl, const std::string &command) {
    char buffer[1024] = {0};
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        std::cout << buffer << std::endl;

        if (std::strncmp(buffer, "READY_FOR_DATA", 14) == 0) {
            if (command == "register") {
                // Запрашиваем данные для регистрации
                std::string email, login, password;
                std::cout << "Enter email: ";
                std::getline(std::cin, email);
                std::cout << "Enter login: ";
                std::getline(std::cin, login);
                std::cout << "Enter password: ";
                std::getline(std::cin, password);

                // Формируем сообщение для отправки на сервер: email;login;password
                std::string data_message = email + ";" + login + ";" + password;

                // Отправляем сообщение на сервер
                SSL_write(ssl, data_message.c_str(), data_message.length());
            } else if (command == "login") {
                // Запрашиваем логин и пароль
                std::string login, password;
                std::cout << "Enter login: ";
                std::getline(std::cin, login);
                std::cout << "Enter password: ";
                std::getline(std::cin, password);

                // Формируем сообщение для отправки на сервер: login;password
                std::string data_message = login + ";" + password;

                // Отправляем сообщение на сервер
                SSL_write(ssl, data_message.c_str(), data_message.length());
            }
        }
    }
}

int main() {
    init_openssl();
    SSL_CTX *ctx = create_context();

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_fd);

    connect_to_server(ssl);

    std::cout << "Enter command: register/login/exit\n";
    std::string command;
    while (true) {
        std::cout << "> ";
        std::getline(std::cin, command);
        if (command.empty()) continue;

        SSL_write(ssl, command.c_str(), command.length());

        if (command == "exit") {
            break;
        }

        handle_response(ssl, command);
    }

    SSL_free(ssl);
    close(server_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
