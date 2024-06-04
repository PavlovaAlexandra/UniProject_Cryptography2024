#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sqlite3.h> // Include SQLite library
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <random>

#include "hashing.cpp"

// Функция для создания таблицы сообщений
// Function to create messages table
void create_messages_table(sqlite3 *db) {
    const char *create_table_query = "CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, title TEXT, author TEXT, body TEXT);";
    int create_table_result = sqlite3_exec(db, create_table_query, NULL, NULL, NULL);
    if (create_table_result != SQLITE_OK) {
        std::cerr << "Error: Failed to create messages table.\n";
    }
}

// Функция для чтения последних n сообщений
// Function to read the last n messages
void list_messages(int client_socket, int n, sqlite3 *db) {
    char buffer[1024];
    snprintf(buffer, sizeof(buffer), "SELECT * FROM messages ORDER BY id DESC LIMIT %d;", n);
    sqlite3_stmt *statement;
    int prepare_result = sqlite3_prepare_v2(db, buffer, -1, &statement, NULL);
    if (prepare_result != SQLITE_OK) {
        std::cerr << "Error: Failed to prepare SQL statement.\n";
        return;
    }

    // Выполнение запроса
    // Execute query
    std::string message = "Recent messages:\n";
    while (sqlite3_step(statement) == SQLITE_ROW) {
        int id = sqlite3_column_int(statement, 0);
        const unsigned char *title = sqlite3_column_text(statement, 1);
        const unsigned char *author = sqlite3_column_text(statement, 2);
        message += std::to_string(id) + ": " + (const char *)title + " by " + (const char *)author + "\n";
    }
    sqlite3_finalize(statement);

    // Отправка сообщения клиенту
    // Send message to client
    send(client_socket, message.c_str(), message.length(), 0);
}

// Функция для загрузки сообщения по его идентификатору
// Function to get a message by its ID
void get_message(int client_socket, int mid, sqlite3 *db) {
    char buffer[1024];
    snprintf(buffer, sizeof(buffer), "SELECT * FROM messages WHERE id=%d;", mid);
    sqlite3_stmt *statement;
    int prepare_result = sqlite3_prepare_v2(db, buffer, -1, &statement, NULL);
    if (prepare_result != SQLITE_OK) {
        std::cerr << "Error: Failed to prepare SQL statement.\n";
        return;
    }

    // Выполнение запроса
    // Execute query
    if (sqlite3_step(statement) == SQLITE_ROW) {
        const unsigned char *title = sqlite3_column_text(statement, 1);
        const unsigned char *author = sqlite3_column_text(statement, 2);
        const unsigned char *body = sqlite3_column_text(statement, 3);
        std::string message = "Message:\nTitle: " + std::string((const char *)title) + "\nAuthor: " + std::string((const char *)author) + "\nBody: " + std::string((const char *)body) + "\n";
        send(client_socket, message.c_str(), message.length(), 0);
    } else {
        const char *error_message = "Message not found.\n";
        send(client_socket, error_message, strlen(error_message), 0);
    }
    sqlite3_finalize(statement);
}

// Функция для добавления нового сообщения
// Function to add a new message
void add_message(int client_socket, const char *author, sqlite3 *db) {
    char buffer[1024];
    const char *prompt = "Enter title and body separated by semicolon (;): ";
    send(client_socket, prompt, strlen(prompt), 0);

    // Принятие данных от клиента (title;body)
    // Receive data from client (title;body)
    ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) {
        std::cerr << "Error: Failed to receive data from client.\n";
        return;
    }
    buffer[bytes_received] = '\0';

    // Парсинг данных от клиента (предполагаем, что данные разделены символом ';')
    // Parse data from client (assuming data is separated by ';')
    char *title = strtok(buffer, ";");
    char *body = strtok(NULL, ";");

    // Вставка данных нового сообщения в базу данных
    // Insert new message data into the database
    char sql_query[512];
    snprintf(sql_query, sizeof(sql_query), "INSERT INTO messages (title, author, body) VALUES ('%s', '%s', '%s');", title, author, body);
    int result = sqlite3_exec(db, sql_query, NULL, NULL, NULL);
    if (result != SQLITE_OK) {
        std::cerr << "Error: Failed to add message to database.\n";
        const char *message = "Failed to add message.\n";
        send(client_socket, message, strlen(message), 0);
        return;
    }

    // Отправка подтверждения клиенту
    // Send confirmation to client
    const char *message = "Message added successfully!\n";
    send(client_socket, message, strlen(message), 0);
}

// Функция обработки запросов на выход из системы
// Function to handle logout requests
void handle_logout(int client_socket, bool &loggedIn) {
    const char *message = "Logout successful!\n";
    send(client_socket, message, strlen(message), 0);
    loggedIn = false; // сбрасываем флаг входа
                     // reset login flag
    std::cout << "Client logged out.\n";
}

// Функция обработки запросов на регистрацию новых пользователей
// Function to handle new user registration requests
void handle_registration(int client_socket, sqlite3 *db) {
    char buffer[1024];

    // Запрос информации от пользователя
    // Request information from user
    const char *prompt = "Enter your email, login, and password separated by semicolons (;): ";
    send(client_socket, prompt, strlen(prompt), 0);

    // Принятие данных от клиента (email, login, password)
    // Receive data from client (email, login, password)
    ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) {
        std::cerr << "Error: Failed to receive data from client.\n";
        return;
    }
    buffer[bytes_received] = '\0';

    // Парсинг данных от клиента (предполагаем, что данные разделены символом ';')
    // Parse data from client (assuming data is separated by ';')
    char *email = strtok(buffer, ";");
    char *login = strtok(NULL, ";");
    char *password = strtok(NULL, ";");
    
    std::string salt = generate_salt(8);
    std::string hashed_password = hash_password(password, salt);
    
    // Check for login uniqueness
    char check_query[512];
    snprintf(check_query, sizeof(check_query), "SELECT login FROM users WHERE login='%s';", login);
    sqlite3_stmt *check_statement;
    int prepare_check_result = sqlite3_prepare_v2(db, check_query, -1, &check_statement, NULL);
    if (prepare_check_result != SQLITE_OK) {
        std::cerr << "Error: Failed to prepare SQL statement.\n";
        return;
    }

    int step_check_result = sqlite3_step(check_statement);
    if (step_check_result == SQLITE_ROW) {
        // Логин уже существует, отправка сообщения об ошибке клиенту
        // Login already exists, send error message to client
        const char *message = "Registration failed: login already exists.\n";
        send(client_socket, message, strlen(message), 0);
        sqlite3_finalize(check_statement);
        return;
    }

    sqlite3_finalize(check_statement);

    // Вставка данных нового пользователя в базу данных
    // Insert new user data into the database
    char sql_query[512];
    snprintf(sql_query, sizeof(sql_query), "INSERT INTO users (email, login, password, salt) VALUES ('%s', '%s', '%s', '%s');",
            email, login, hashed_password.c_str(), salt.c_str());
    int result = sqlite3_exec(db, sql_query, NULL, NULL, NULL);
    if (result != SQLITE_OK) {
        std::cerr << "Error: Failed to insert user into database.\n";
        const char *message = "Registration failed.\n";
        send(client_socket, message, strlen(message), 0);
        return;
    }

    // Отправка подтверждения клиенту
    // Send confirmation to client
    const char *message = "Registration successful!\n";
    send(client_socket, message, strlen(message), 0);
    std::cout << "New user registered: " << login << std::endl;
}

// Функция обработки запросов на вход зарегистрированных пользователей
// Function to handle login requests from registered users
void handle_login(int client_socket, sqlite3 *db, bool &loggedIn, std::string &current_user) {
    char buffer[1024];

    // Если пользователь уже вошел в систему, сообщаем ему об этом и завершаем функцию
    // If user is already logged in, notify and exit function
    if (loggedIn) {
        const char *message = "You are already logged in.\n";
        send(client_socket, message, strlen(message), 0);
        return;
    }

    // Запрос логина и пароля от пользователя
    // Request login and password from user
    const char *prompt = "Enter your login and password separated by a semicolon (;): ";
    send(client_socket, prompt, strlen(prompt), 0);

    // Принятие данных от клиента (login, password)
    // Receive data from client (login, password)
    ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) {
        std::cerr << "Error: Failed to receive data from client.\n";
        return;
    }
    buffer[bytes_received] = '\0';

    // Парсинг данных от клиента (предполагаем, что данные разделены символом ';')
    // Parse data from client (assuming data is separated by ';')
    char *login = strtok(buffer, ";");
    char *password = strtok(NULL, ";");

    // Проверка логина и пароля
    // Check login and password
    char sql_query[512];
    snprintf(sql_query, sizeof(sql_query), "SELECT password, salt FROM users WHERE login ='%s'", login);
    sqlite3_stmt *statement;
    int prepare_result = sqlite3_prepare_v2(db, sql_query, -1, &statement, NULL);
    if (prepare_result != SQLITE_OK) {
        std::cerr << "Error: Failed to prepare SQL statement.\n";
        return;
    }

    // Выполнение запроса
    // Execute query
    int step_result = sqlite3_step(statement);
    if (step_result == SQLITE_ROW) {
        const char *stored_hash = reinterpret_cast<const char *>(sqlite3_column_text(statement, 0));
        const char *stored_salt = reinterpret_cast<const char *>(sqlite3_column_text(statement, 1));
        std::string hashed_password = hash_password(password, stored_salt);

        if(hashed_password == stored_hash) {
            const char *message = "Login successful!\n";
            send(client_socket, message, strlen(message), 0);
            loggedIn = true; // set login flag
            current_user = login; // save current user's login
            std::cout << "Client logged in: " << login << std::endl;
        }
        else {
        // User not found, send error message to client
        const char *message = "Login failed: incorrect login or password.\n";
        send(client_socket, message, strlen(message), 0);
        }
    } else {
        // User not found, send error message to client
        const char *message = "Login failed: incorrect login or password.\n";
        send(client_socket, message, strlen(message), 0);
    }

    sqlite3_finalize(statement);
}

// Измененный main для добавления обработки выбора регистрации, входа, выхода и выполнения операций с сообщениями
// Modified main to add handling of registration, login, logout, and message operations
int main() {
    // Создание сокета
    // Create socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        std::cerr << "Error: Could not create socket.\n";
        return EXIT_FAILURE;
    }

    // Настройка адреса сервера
    // Setup server address
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(12345);

    // Привязка сокета к адресу и порту
    // Bind socket to address and port
    if (bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) == -1) {
        std::cerr << "Error: Could not bind socket to address.\n";
        return EXIT_FAILURE;
    }

    // Начало прослушивания подключений
    // Start listening for connections
    if (listen(server_socket, 5) == -1) {
        std::cerr << "Error: Could not listen on socket.\n";
        return EXIT_FAILURE;
    }

    std::cout << "Server listening on port 12345...\n";

    // Открытие соединения с базой данных SQLite
    // Open connection to SQLite database
    sqlite3 *db;
    int db_open_result = sqlite3_open("/home/frank99/NewProjCrypto/UniProject_Cryptography2024/BBS.db", &db);
    if (db_open_result != SQLITE_OK) {
        std::cerr << "Error: Failed to open database.\n";
        return EXIT_FAILURE;
    }

    // Создание таблицы пользователей, если она не существует
    // Create users table if it doesn't exist
    const char *create_table_query = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT, login TEXT UNIQUE, password TEXT, salt TEXT);";
    int create_table_result = sqlite3_exec(db, create_table_query, NULL, NULL, NULL);
    if (create_table_result != SQLITE_OK) {
        std::cerr << "Error: Failed to create users table.\n";
        return EXIT_FAILURE;
    }

    // Создание таблицы сообщений, если она не существует
    // Create messages table if it doesn't exist
    create_messages_table(db);

    bool loggedIn = false; // флаг для отслеживания входа пользователя
                          // flag to track user login status
    std::string current_user; // переменная для хранения логина текущего пользователя
                             // variable to store current user's login

    // Принятие и обработка подключений
    // Accept and handle connections
    while (true) {
        // Принятие нового подключения
        // Accept new connection
        int client_socket = accept(server_socket, NULL, NULL);
        if (client_socket == -1) {
            std::cerr << "Error: Could not accept incoming connection.\n";
            continue;
        }

        std::cout << "New client connected.\n";

        // Цикл обработки запросов клиента
        // Loop to handle client requests
        while (true) {
            // Если пользователь уже вошел в систему, предлагаем только logout
            // If user is already logged in, only offer logout
            if (loggedIn) {
                const char *prompt = "Enter 'logout' to logout, 'list <n>' to list last n messages, 'get <mid>' to get message by id, or 'add' to add a new message: ";
                send(client_socket, prompt, strlen(prompt), 0);
            } else {
                // Запрос выбора регистрации, входа или выхода от клиента
                // Request registration, login, or exit from client
                const char *prompt = "Enter 'register' for registration, 'login' for login, or 'exit' to exit: ";
                send(client_socket, prompt, strlen(prompt), 0);
            }

            char choice[256];
            ssize_t choice_received = recv(client_socket, choice, sizeof(choice), 0);
            if (choice_received <= 0) {
                std::cerr << "Error: Failed to receive choice from client.\n";
                close(client_socket);
                break; // выход из цикла обработки запросов клиента
                      // exit client request handling loop
            }
            choice[choice_received] = '\0';

            // Обработка выбора
            // Handle choice
            if (strcmp(choice, "register\n") == 0) {
                handle_registration(client_socket, db);
            } else if (strcmp(choice, "login\n") == 0) {
                handle_login(client_socket, db, loggedIn, current_user);
            } else if (strcmp(choice, "logout\n") == 0) {
                handle_logout(client_socket, loggedIn);
            } else if (strncmp(choice, "list ", 5) == 0) {
                int n = atoi(choice + 5);
                list_messages(client_socket, n, db);
            } else if (strncmp(choice, "get ", 4) == 0) {
                int mid = atoi(choice + 4);
                get_message(client_socket, mid, db);
            } else if (strcmp(choice, "add\n") == 0) {
                add_message(client_socket, current_user.c_str(), db);
            } else if (strcmp(choice, "exit\n") == 0) {
                std::cout << "Client requested exit.\n";
                close(client_socket);
                break; // выход из цикла обработки запросов клиента
                      // exit client request handling loop
            } else {
                const char *message = "Invalid choice.\n";
                send(client_socket, message, strlen(message), 0);
            }
        }
    }

    // Закрытие серверного сокета и соединения с базой данных
    // Close server socket and database connection
    close(server_socket);
    sqlite3_close(db);

    return EXIT_SUCCESS;
}