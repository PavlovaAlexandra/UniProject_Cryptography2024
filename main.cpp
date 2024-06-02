#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sqlite3.h>
#include "hashing.h"

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method = SSLv23_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate_file(ctx, "/Users/alexandra/MasterDegree/PisaStudy/2semester/AppliedCryptography/MyProject/Сertificate/cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "/Users/alexandra/MasterDegree/PisaStudy/2semester/AppliedCryptography/MyProject/Сertificate/key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void handle_registration(SSL *ssl, sqlite3 *db) {
    const char *prompt = "READY_FOR_DATA\n";
    SSL_write(ssl, prompt, strlen(prompt));

    char buffer[1024] = {0};
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes_received <= 0) {
        std::cerr << "Error: Failed to receive data from client.\n";
        return;
    }
    buffer[bytes_received] = '\0';

    std::string data(buffer);
    size_t pos1 = data.find(';');
    size_t pos2 = data.find(';', pos1 + 1);
    if (pos1 == std::string::npos || pos2 == std::string::npos) {
        const char *error = "Invalid data format\n";
        SSL_write(ssl, error, strlen(error));
        return;
    }

    std::string email = data.substr(0, pos1);
    std::string login = data.substr(pos1 + 1, pos2 - pos1 - 1);
    std::string password = data.substr(pos2 + 1);

    std::string salt = generate_salt(16); // Генерируем соль длиной 16 символов
    std::string hashed_password = hash_password(password, salt);

    std::string sql = "INSERT INTO users (email, login, password, salt) VALUES (?, ?, ?, ?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        const char *error = "Failed to prepare statement\n";
        SSL_write(ssl, error, strlen(error));
        return;
    }

    if (sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 2, login.c_str(), -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 3, hashed_password.c_str(), -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 4, salt.c_str(), -1, SQLITE_STATIC) != SQLITE_OK) {
        const char *error = "Failed to bind values\n";
        SSL_write(ssl, error, strlen(error));
        sqlite3_finalize(stmt);
        return;
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        const char *error = "Failed to execute statement\n";
        SSL_write(ssl, error, strlen(error));
    } else {
        const char *success = "Registration successful\n";
        SSL_write(ssl, success, strlen(success));
    }
    sqlite3_finalize(stmt);
}

void handle_login(SSL *ssl, sqlite3 *db, bool &loggedIn, std::string &current_user) {
    const char *prompt = "READY_FOR_DATA\n";
    SSL_write(ssl, prompt, strlen(prompt));

    char buffer[1024] = {0};
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes_received <= 0) {
        std::cerr << "Error: Failed to receive data from client.\n";
        return;
    }
    buffer[bytes_received] = '\0';

    std::string data(buffer);
    size_t pos = data.find(';');
    if (pos == std::string::npos) {
        const char *error = "Invalid data format\n";
        SSL_write(ssl, error, strlen(error));
        return;
    }

    std::string login = data.substr(0, pos);
    std::string password = data.substr(pos + 1);

    std::string sql = "SELECT password, salt FROM users WHERE login = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        const char *error = "Failed to prepare statement\n";
        SSL_write(ssl, error, strlen(error));
        return;
    }

    if (sqlite3_bind_text(stmt, 1, login.c_str(), -1, SQLITE_STATIC) != SQLITE_OK) {
        const char *error = "Failed to bind values\n";
        SSL_write(ssl, error, strlen(error));
        sqlite3_finalize(stmt);
        return;
    }

    int step = sqlite3_step(stmt);
    if (step == SQLITE_ROW) {
        std::string stored_password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        std::string salt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        std::string hashed_password = hash_password(password, salt);

        if (hashed_password == stored_password) {
            const char *success = "Login successful\n";
            SSL_write(ssl, success, strlen(success));
            loggedIn = true;
            current_user = login;
        } else {
            const char *error = "Invalid login or password\n";
            SSL_write(ssl, error, strlen(error));
        }
    } else {
        const char *error = "Invalid login or password\n";
        SSL_write(ssl, error, strlen(error));
    }
    sqlite3_finalize(stmt);
}

void handle_command(SSL *ssl, sqlite3 *db, bool &loggedIn, std::string &current_user) {
    char buffer[1024] = {0};
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes_received <= 0) {
        std::cerr << "Error: Failed to receive data from client.\n";
        return;
    }
    buffer[bytes_received] = '\0';
    std::string command(buffer);

    if (command == "register") {
        handle_registration(ssl, db);
    } else if (command == "login") {
        handle_login(ssl, db, loggedIn, current_user);
    } else if (command == "exit") {
        const char *response = "Goodbye!\n";
        SSL_write(ssl, response, strlen(response));
        loggedIn = false;
    } else {
        const char *unknown = "Unknown command\n";
        SSL_write(ssl, unknown, strlen(unknown));
    }
}

int main() {
    init_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket");
        return EXIT_FAILURE;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(server_fd);
        return EXIT_FAILURE;
    }

    if (listen(server_fd, 10) == -1) {
        perror("listen");
        close(server_fd);
        return EXIT_FAILURE;
    }

    sqlite3 *db;
    int rc = sqlite3_open("users.db", &db);
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return EXIT_FAILURE;
    }

    SSL *ssl;
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    int new_socket;
    bool loggedIn = false;
    std::string current_user;

    while (true) {
        new_socket = accept(server_fd, (struct sockaddr *)&cli_addr, &cli_len);
        if (new_socket == -1) {
            perror("accept");
            close(server_fd);
            return EXIT_FAILURE;
        }

        ssl = SSL_new(ctx);
        if (!ssl) {
            std::cerr << "Unable to create SSL structure\n";
            close(new_socket);
            continue;
        }

        SSL_set_fd(ssl, new_socket);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(new_socket);
            continue;
        }

        std::cout << "Connected with client\n";

        pid_t pid = fork();
        if (pid < 0) {
            std::cerr << "Error in fork\n";
            close(new_socket);
            continue;
        } else if (pid == 0) { // Child process
            close(server_fd); // Close server socket in child process
            while (true) {
                handle_command(ssl, db, loggedIn, current_user);
                if (!loggedIn) break;
            }
            close(new_socket);
            return EXIT_SUCCESS;
        } else { // Parent process
            close(new_socket); // Close client socket in parent process
        }
    }

    close(server_fd);
    sqlite3_close(db);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return EXIT_SUCCESS;
}
