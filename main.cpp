#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "sqlite3.h"

// Функция обработки запросов на регистрацию новых пользователей
void handle_registration(int client_socket, sqlite3 *db) {
    char buffer[1024];

    // Запрос информации от пользователя
    const char *prompt = "Enter your email, login, and password separated by semicolons (;), or enter 'logout' to exit: ";
    send(client_socket, prompt, strlen(prompt), 0);

    // Принятие данных от клиента (email, login, password)
    ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) {
        std::cerr << "Error: Failed to receive data from client.\n";
        return;
    }
    buffer[bytes_received] = '\0';

    // Проверка на выход
    if (strcmp(buffer, "logout\n") == 0) {
        std::cout << "Client logged out.\n";
        return;
    }

    // Парсинг данных от клиента (предполагаем, что данные разделены символом ';')
    char *email = strtok(buffer, ";");
    char *login = strtok(NULL, ";");
    char *password = strtok(NULL, ";");

    // Вставка данных нового пользователя в базу данных
    char sql_query[512];
    snprintf(sql_query, sizeof(sql_query), "INSERT INTO users (email, login, password) VALUES ('%s', '%s', '%s');",
            email, login, password);
    int result = sqlite3_exec(db, sql_query, NULL, NULL, NULL);
    if (result != SQLITE_OK) {
        std::cerr << "Error: Failed to insert user into database.\n";
        const char *message = "Registration failed.\n";
        send(client_socket, message, strlen(message), 0);
        return;
    }

    // Отправка подтверждения клиенту
    const char *message = "Registration successful!\n";
    send(client_socket, message, strlen(message), 0);
    std::cout << "New user registered: " << login << std::endl;
}

// Функция обработки запросов на вход зарегистрированных пользователей
void handle_login(int client_socket, sqlite3 *db, bool &loggedIn) {
    char buffer[1024];

    // Если пользователь уже вошел в систему, сообщаем ему об этом и завершаем функцию
    if (loggedIn) {
        const char *message = "You are already logged in.\n";
        send(client_socket, message, strlen(message), 0);
        return;
    }

    // Запрос информации от пользователя
    const char *prompt = "Enter your login and password separated by semicolons (;) or enter 'logout' to exit: ";
    send(client_socket, prompt, strlen(prompt), 0);

    // Принятие данных от клиента (login, password)
    ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) {
        std::cerr << "Error: Failed to receive data from client.\n";
        return;
    }
    buffer[bytes_received] = '\0';

    // Проверка на выход
    if (strcmp(buffer, "logout\n") == 0) {
        std::cout << "Client logged out.\n";
        return;
    }

    // Парсинг данных от клиента (предполагаем, что данные разделены символом ';')
    char *login = strtok(buffer, ";");
    char *password = strtok(NULL, ";");

    // Поиск пользователя в базе данных
    char sql_query[512];
    snprintf(sql_query, sizeof(sql_query), "SELECT * FROM users WHERE login='%s' AND password='%s';",
            login, password);
    sqlite3_stmt *statement;
    int prepare_result = sqlite3_prepare_v2(db, sql_query, -1, &statement, NULL);
    if (prepare_result != SQLITE_OK) {
        std::cerr << "Error: Failed to prepare SQL statement.\n";
        return;
    }

    // Выполнение запроса
    int step_result = sqlite3_step(statement);
    if (step_result == SQLITE_ROW) {
        // Пользователь найден, отправка подтверждения клиенту
        const char *message = "Login successful!\n";
        send(client_socket, message, strlen(message), 0);
        loggedIn = true; // устанавливаем флаг входа
        std::cout << "Client logged in: " << login << std::endl;
    } else {
        // Пользователь не найден, отправка сообщения об ошибке клиенту
        const char *message = "Login failed: incorrect login or password.\n";
        send(client_socket, message, strlen(message), 0);
    }

    sqlite3_finalize(statement);
}

// Функция обработки запросов на выход из системы
void handle_logout(int client_socket, bool &loggedIn) {
    const char *message = "Logout successful!\n";
    send(client_socket, message, strlen(message), 0);
    loggedIn = false; // сбрасываем флаг входа
    std::cout << "Client logged out.\n";
}

// Измененный main для добавления обработки выбора регистрации, входа и выхода
int main() {
    // Создание сокета
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        std::cerr << "Error: Could not create socket.\n";
        return EXIT_FAILURE;
    }

    // Настройка адреса сервера
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(12345);

    // Привязка сокета к адресу и порту
    if (bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) == -1) {
        std::cerr << "Error: Could not bind socket to address.\n";
        return EXIT_FAILURE;
    }

    // Начало прослушивания подключений
    if (listen(server_socket, 5) == -1) {
        std::cerr << "Error: Could not listen on socket.\n";
        return EXIT_FAILURE;
    }

    std::cout << "Server listening on port 12345...\n";

    // Открытие соединения с базой данных SQLite
    sqlite3 *db;
    int db_open_result = sqlite3_open("/home/frank99/NewProjCrypto/UniProject_Cryptography2024/BBS.db", &db);
    if (db_open_result != SQLITE_OK) {
        std::cerr << "Error: Failed to open database.\n";
        return EXIT_FAILURE;
    }

    // Создание таблицы пользователей, если она не существует
    const char *create_table_query = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT, login TEXT UNIQUE, password TEXT);";
    int create_table_result = sqlite3_exec(db, create_table_query, NULL, NULL, NULL);
    if (create_table_result != SQLITE_OK) {
        std::cerr << "Error: Failed to create users table.\n";
        return EXIT_FAILURE;
    }

    bool loggedIn = false; // флаг для отслеживания входа пользователя

    // Принятие и обработка подключений
    while (true) {
        // Принятие нового подключения
        int client_socket = accept(server_socket, NULL, NULL);
        if (client_socket == -1) {
            std::cerr << "Error: Could not accept incoming connection.\n";
            continue;
        }

        std::cout << "New client connected.\n";

        // Цикл обработки запросов клиента
        while (true) {
            // Если пользователь уже вошел в систему, предлагаем только logout
            if (loggedIn) {
                const char *prompt = "Enter 'logout' to logout: ";
                send(client_socket, prompt, strlen(prompt), 0);
            } else {
                // Запрос выбора регистрации, входа или выхода от клиента
                const char *prompt = "Enter 'register' for registration, 'login' for login, or 'exit' to exit: ";
                send(client_socket, prompt, strlen(prompt), 0);
            }

            char choice[10];
            ssize_t choice_received = recv(client_socket, choice, sizeof(choice), 0);
            if (choice_received <= 0) {
                std::cerr << "Error: Failed to receive choice from client.\n";
                close(client_socket);
                break; // выход из цикла обработки запросов клиента
            }
            choice[choice_received] = '\0';

            // Обработка выбора
            if (strcmp(choice, "register\n") == 0) {
                handle_registration(client_socket, db);
            } else if (strcmp(choice, "login\n") == 0) {
                handle_login(client_socket, db, loggedIn);
            } else if (strcmp(choice, "logout\n") == 0) {
                handle_logout(client_socket, loggedIn);
            } else if (strcmp(choice, "exit\n") == 0) {
                std::cout << "Client requested exit.\n";
                close(client_socket);
                break; // выход из цикла обработки запросов клиента
            } else {
                const char *message = "Invalid choice.\n";
                send(client_socket, message, strlen(message), 0);
            }
        }
    }

    // Закрытие серверного сокета и соединения с базой данных
    close(server_socket);
    sqlite3_close(db);

    return EXIT_SUCCESS;
}