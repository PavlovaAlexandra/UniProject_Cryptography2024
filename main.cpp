#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <Winsock2.h>
#include <sqlite3.h>
#include <curl/curl.h> // Include libcurl for email sending
#include <ctime>

// Function to generate a random challenge token
std::string generate_challenge()
{
    std::srand(std::time(0));
    std::string challenge = std::to_string(std::rand());
    return challenge;
}

// Function to send an email using libcurl
bool send_email(const char *email, const char *challenge)
{
    CURL *curl;
    CURLcode res = CURLE_OK;

    curl = curl_easy_init();
    if (curl)
    {
        struct curl_slist *recipients = NULL;
        curl_easy_setopt(curl, CURLOPT_USERNAME, "othman.elhammali@gmail.com"); // Set your email
        curl_easy_setopt(curl, CURLOPT_PASSWORD, "hggih;fv1000lvi");            // Set your email password
        curl_easy_setopt(curl, CURLOPT_URL, "smtps://smtp.gmail.com:465");      // SMTP server

        curl_easy_setopt(curl, CURLOPT_MAIL_FROM, "othman.elhammali@gmail.com"); // Sender email
        recipients = curl_slist_append(recipients, email);                       // Recipient email
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        std::string payload = "Subject: BBS Registration Challenge\n\n" + std::string(challenge);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, NULL);
        curl_easy_setopt(curl, CURLOPT_READDATA, &payload);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

        // Path to the self-signed certificate
        curl_easy_setopt(curl, CURLOPT_CAINFO, "C:/Users/othma/Desktop/Cryptography/Project/MyProject/localhost.crt");

        res = curl_easy_perform(curl);

        if (res != CURLE_OK)
        {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }

        curl_slist_free_all(recipients);
        curl_easy_cleanup(curl);
    }
    return (res == CURLE_OK);
}

void handle_registration(int client_socket, sqlite3 *db)
{
    char buffer[1024];

    // Request information from user
    const char *prompt = "Enter your email, login, and password separated by semicolons (;), or enter 'logout' to exit: ";
    send(client_socket, prompt, strlen(prompt), 0);

    // Receive data from client (email, login, password)
    ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0)
    {
        std::cerr << "Error: Failed to receive data from client.\n";
        return;
    }
    buffer[bytes_received] = '\0';

    // Check for exit
    if (strcmp(buffer, "logout\n") == 0)
    {
        std::cout << "Client logged out.\n";
        return;
    }

    // Parse client data (assume data is separated by ';')
    char *email = strtok(buffer, ";");
    char *login = strtok(NULL, ";");
    char *password = strtok(NULL, ";");

    // Generate a challenge token
    std::string challenge = generate_challenge();

    // Send challenge to user's email
    if (!send_email(email, challenge.c_str()))
    {
        std::cerr << "Error: Failed to send challenge email.\n";
        const char *message = "Registration failed: could not send challenge email.\n";
        send(client_socket, message, strlen(message), 0);
        return;
    }

    // Ask user to enter the challenge token received via email
    const char *challenge_prompt = "Enter the challenge token sent to your email: ";
    send(client_socket, challenge_prompt, strlen(challenge_prompt), 0);

    // Receive challenge response from client
    bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0)
    {
        std::cerr << "Error: Failed to receive challenge response from client.\n";
        return;
    }
    buffer[bytes_received] = '\0';

    // Verify the challenge token
    if (challenge != std::string(buffer))
    {
        std::cerr << "Error: Challenge token does not match.\n";
        const char *message = "Registration failed: incorrect challenge token.\n";
        send(client_socket, message, strlen(message), 0);
        return;
    }

    // Insert new user data into the database
    char sql_query[512];
    snprintf(sql_query, sizeof(sql_query), "INSERT INTO users (email, login, password) VALUES ('%s', '%s', '%s');",
             email, login, password);
    int result = sqlite3_exec(db, sql_query, NULL, NULL, NULL);
    if (result != SQLITE_OK)
    {
        std::cerr << "Error: Failed to insert user into database.\n";
        const char *message = "Registration failed.\n";
        send(client_socket, message, strlen(message), 0);
        return;
    }

    // Send confirmation to client
    const char *message = "Registration successful!\n";
    send(client_socket, message, strlen(message), 0);
    std::cout << "New user registered: " << login << std::endl;
}

void handle_login(int client_socket, sqlite3 *db, bool &loggedIn)
{
    char buffer[1024];

    if (loggedIn)
    {
        const char *message = "You are already logged in.\n";
        send(client_socket, message, strlen(message), 0);
        return;
    }

    const char *prompt = "Enter your login and password separated by semicolons (;) or enter 'logout' to exit: ";
    send(client_socket, prompt, strlen(prompt), 0);

    ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0)
    {
        std::cerr << "Error: Failed to receive data from client.\n";
        return;
    }
    buffer[bytes_received] = '\0';

    if (strcmp(buffer, "logout\n") == 0)
    {
        std::cout << "Client logged out.\n";
        return;
    }

    char *login = strtok(buffer, ";");
    char *password = strtok(NULL, ";");

    char sql_query[512];
    snprintf(sql_query, sizeof(sql_query), "SELECT * FROM users WHERE login='%s' AND password='%s';",
             login, password);
    sqlite3_stmt *statement;
    int prepare_result = sqlite3_prepare_v2(db, sql_query, -1, &statement, NULL);
    if (prepare_result != SQLITE_OK)
    {
        std::cerr << "Error: Failed to prepare SQL statement.\n";
        return;
    }

    int step_result = sqlite3_step(statement);
    if (step_result == SQLITE_ROW)
    {
        const char *message = "Login successful!\n";
        send(client_socket, message, strlen(message), 0);
        loggedIn = true;
        std::cout << "Client logged in: " << login << std::endl;
    }
    else
    {
        const char *message = "Login failed: incorrect login or password.\n";
        send(client_socket, message, strlen(message), 0);
    }

    sqlite3_finalize(statement);
}

void handle_logout(int client_socket, bool &loggedIn)
{
    const char *message = "Logout successful!\n";
    send(client_socket, message, strlen(message), 0);
    loggedIn = false;
    std::cout << "Client logged out.\n";
}

int main()
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cerr << "WSAStartup failed.\n";
        return EXIT_FAILURE;
    }

    SOCKET server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET)
    {
        std::cerr << "Error: Could not create socket.\n";
        WSACleanup();
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(12345);

    if (bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) == -1)
    {
        std::cerr << "Error: Could not bind socket to address.\n";
        return EXIT_FAILURE;
    }

    if (listen(server_socket, 5) == -1)
    {
        std::cerr << "Error: Could not listen on socket.\n";
        return EXIT_FAILURE;
    }

    std::cout << "Server listening on port 12345...\n";

    sqlite3 *db;
    int db_open_result = sqlite3_open("/Users/othma/Desktop/Cryptography/Project/MyProject/BBS.db", &db);
    if (db_open_result != SQLITE_OK)
    {
        std::cerr << "Error: Failed to open database.\n";
        return EXIT_FAILURE;
    }

    const char *create_table_query = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT, login TEXT UNIQUE, password TEXT);";
    int create_table_result = sqlite3_exec(db, create_table_query, NULL, NULL, NULL);
    if (create_table_result != SQLITE_OK)
    {
        std::cerr << "Error: Failed to create users table.\n";
        return EXIT_FAILURE;
    }

    bool loggedIn = false;

    while (true)
    {
        int client_socket = accept(server_socket, NULL, NULL);
        if (client_socket == -1)
        {
            std::cerr << "Error: Could not accept incoming connection.\n";
            continue;
        }

        std::cout << "New client connected.\n";

        while (true)
        {
            if (loggedIn)
            {
                const char *prompt = "Enter 'logout' to logout: ";
                send(client_socket, prompt, strlen(prompt), 0);
            }
            else
            {
                const char *prompt = "Enter 'register' for registration, 'login' for login, or 'exit' to exit: ";
                send(client_socket, prompt, strlen(prompt), 0);
            }

            char choice[10];
            ssize_t choice_received = recv(client_socket, choice, sizeof(choice), 0);
            if (choice_received <= 0)
            {
                std::cerr << "Error: Failed to receive choice from client.\n";
                close(client_socket);
                break;
            }
            choice[choice_received] = '\0';

            if (strcmp(choice, "register\n") == 0)
            {
                handle_registration(client_socket, db);
            }
            else if (strcmp(choice, "login\n") == 0)
            {
                handle_login(client_socket, db, loggedIn);
            }
            else if (strcmp(choice, "logout\n") == 0)
            {
                handle_logout(client_socket, loggedIn);
            }
            else if (strcmp(choice, "exit\n") == 0)
            {
                std::cout << "Client requested exit.\n";
                close(client_socket);
                break;
            }
            else
            {
                const char *message = "Invalid choice.\n";
                send(client_socket, message, strlen(message), 0);
            }
        }
    }

    close(server_socket);
    sqlite3_close(db);

    WSACleanup();
    return EXIT_SUCCESS;
}
