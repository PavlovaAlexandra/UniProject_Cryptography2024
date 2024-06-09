#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

// Receive a message from the client
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

// Send a message to the client
bool sendMessageToClient(int client_sock, const std::string &message)
{
    if (send(client_sock, message.c_str(), message.length(), 0) == -1)
    {
        std::cerr << "Send failed: " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}

// Function to output RSA keys in PEM format
void printRSAKey(EVP_PKEY *pkey, bool isPrivate)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (isPrivate)
    {
        PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    }
    else
    {
        PEM_write_bio_PUBKEY(bio, pkey);
    }
    char *key_data = NULL;
    long len = BIO_get_mem_data(bio, &key_data);
    std::string key_str(key_data, len);
    std::cout << key_str << std::endl;
    BIO_free(bio);
}

// Generate a random number
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

// Sign a message with the RSA private key
bool signMessage(EVP_PKEY *pkey, const std::string &message, std::string &signature)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        std::cerr << "Failed to create EVP_MD_CTX" << std::endl;
        return false;
    }

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1)
    {
        std::cerr << "EVP_DigestSignInit failed" << std::endl;
        EVP_MD_CTX_free(ctx);
        return false;
    }

    if (EVP_DigestSignUpdate(ctx, message.c_str(), message.length()) != 1)
    {
        std::cerr << "EVP_DigestSignUpdate failed" << std::endl;
        EVP_MD_CTX_free(ctx);
        return false;
    }

    size_t sig_len;
    if (EVP_DigestSignFinal(ctx, NULL, &sig_len) != 1)
    {
        std::cerr << "EVP_DigestSignFinal failed to get length" << std::endl;
        EVP_MD_CTX_free(ctx);
        return false;
    }

    unsigned char *sig = new unsigned char[sig_len];
    if (EVP_DigestSignFinal(ctx, sig, &sig_len) != 1)
    {
        std::cerr << "EVP_DigestSignFinal failed" << std::endl;
        delete[] sig;
        EVP_MD_CTX_free(ctx);
        return false;
    }

    signature.assign((char *)sig, sig_len);
    delete[] sig;
    EVP_MD_CTX_free(ctx);
    return true;
}

// Function to convert a string to a hexadecimal representation
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

// Function to print certificate
void printCertificate(const std::string &cert)
{
    std::cout << "Certificate:\n" << cert << std::endl;
}

int main()
{
    // Load the server's private key
    EVP_PKEY *server_pkey = NULL;
    FILE *privkey_file = fopen("Server/server_private_key.pem", "r");
    if (!privkey_file)
    {
        std::cerr << "Unable to open server private key file" << std::endl;
        return -1;
    }
    server_pkey = PEM_read_PrivateKey(privkey_file, NULL, NULL, NULL);
    fclose(privkey_file);
    if (!server_pkey)
    {
        std::cerr << "Unable to read server private key" << std::endl;
        return -1;
    }

    std::cout << "Server private key loaded" << std::endl;
    printRSAKey(server_pkey, true);

    // Load the server's certificate
    X509 *server_cert = NULL;
    FILE *cert_file = fopen("Server/server_cert.pem", "r");
    if (!cert_file)
    {
        std::cerr << "Unable to open server certificate file" << std::endl;
        EVP_PKEY_free(server_pkey);
        return -1;
    }
    server_cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    if (!server_cert)
    {
        std::cerr << "Unable to read server certificate" << std::endl;
        EVP_PKEY_free(server_pkey);
        return -1;
    }

    std::cout << "Server certificate loaded" << std::endl;

    // Create the socket
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == -1)
    {
        std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
        EVP_PKEY_free(server_pkey);
        X509_free(server_cert);
        return -1;
    }

    // Configure server address and port
    struct sockaddr_in serv_addr, client_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    // Bind the socket
    if (bind(server_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        std::cerr << "Bind failed: " << strerror(errno) << std::endl;
        close(server_sock);
        EVP_PKEY_free(server_pkey);
        X509_free(server_cert);
        return -1;
    }

    // Listen for incoming connections
    if (listen(server_sock, 1) == -1)
    {
        std::cerr << "Listen failed: " << strerror(errno) << std::endl;
        close(server_sock);
        EVP_PKEY_free(server_pkey);
        X509_free(server_cert);
        return -1;
    }

    socklen_t client_len = sizeof(client_addr);
    int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
    if (client_sock == -1)
    {
        std::cerr << "Accept failed: " << strerror(errno) << std::endl;
        close(server_sock);
        EVP_PKEY_free(server_pkey);
        X509_free(server_cert);
        return -1;
    }

    std::cout << "Client connected" << std::endl;

    // Generate temporary RSA key pair
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
    {
        std::cerr << "EVP_PKEY_CTX_new_id failed" << std::endl;
        close(client_sock);
        close(server_sock);
        EVP_PKEY_free(server_pkey);
        X509_free(server_cert);
        return -1;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        std::cerr << "EVP_PKEY_keygen_init failed" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        close(client_sock);
        close(server_sock);
        EVP_PKEY_free(server_pkey);
        X509_free(server_cert);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
    {
        std::cerr << "EVP_PKEY_CTX_set_rsa_keygen_bits failed" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        close(client_sock);
        close(server_sock);
        EVP_PKEY_free(server_pkey);
        X509_free(server_cert);
        return -1;
    }

    EVP_PKEY *temp_pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &temp_pkey) <= 0)
    {
        std::cerr << "EVP_PKEY_keygen failed" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        close(client_sock);
        close(server_sock);
        EVP_PKEY_free(server_pkey);
        X509_free(server_cert);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);

    std::cout << "Temporary RSA keys generated" << std::endl;
    std::cout << "Temporary public key:" << std::endl;
    printRSAKey(temp_pkey, false);
    std::cout << "Temporary private key:" << std::endl;
    printRSAKey(temp_pkey, true);

    // Receive the random number R from the client
    std::string R = receiveMessageFromClient(client_sock);
    if (R.empty())
    {
        close(client_sock);
        close(server_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        X509_free(server_cert);
        return -1;
    }

    std::cout << "Random number R received from client: " << stringToHex(R) << std::endl;

    // Create the message to be signed (R + temporary public key)
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, temp_pkey);
    char *temp_pub_key_data = NULL;
    long temp_pub_key_len = BIO_get_mem_data(bio, &temp_pub_key_data);
    std::string temp_pub_key_str(temp_pub_key_data, temp_pub_key_len);
    BIO_free(bio);

    std::string message_to_sign = R + temp_pub_key_str;

    // Sign the message
    std::string signature;
    if (!signMessage(server_pkey, message_to_sign, signature))
    {
        std::cerr << "Signature creation failed" << std::endl;
        close(client_sock);
        close(server_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        X509_free(server_cert);
        return -1;
    }

    std::cout << "Message signed" << std::endl;

    // Send the temporary public key and the signature to the client
    if (!sendMessageToClient(client_sock, temp_pub_key_str) || !sendMessageToClient(client_sock, signature))
    {
        close(client_sock);
        close(server_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        X509_free(server_cert);
        return -1;
    }

    // Send the server's certificate to the client
    BIO *cert_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(cert_bio, server_cert);
    char *cert_data = NULL;
    long cert_len = BIO_get_mem_data(cert_bio, &cert_data);
    std::string cert_str(cert_data, cert_len);
    BIO_free(cert_bio);

    if (!sendMessageToClient(client_sock, cert_str))
    {
        close(client_sock);
        close(server_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        X509_free(server_cert);
        return -1;
    }

    std::cout << "Temporary public key, signature, and server certificate sent to client" << std::endl;

    // Receive the encrypted session key from the client
    std::string encrypted_session_key = receiveMessageFromClient(client_sock);
    if (encrypted_session_key.empty())
    {
        close(client_sock);
        close(server_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        X509_free(server_cert);
        return -1;
    }

    std::cout << "Received encrypted session key: " << stringToHex(encrypted_session_key) << std::endl;

    // Decrypt the session key with the temporary private key
    EVP_PKEY_CTX *decrypt_ctx = EVP_PKEY_CTX_new(temp_pkey, NULL);
    if (!decrypt_ctx)
    {
        std::cerr << "EVP_PKEY_CTX_new failed" << std::endl;
        close(client_sock);
        close(server_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        X509_free(server_cert);
        return -1;
    }

    if (EVP_PKEY_decrypt_init(decrypt_ctx) <= 0)
    {
        std::cerr << "EVP_PKEY_decrypt_init failed" << std::endl;
        EVP_PKEY_CTX_free(decrypt_ctx);
        close(client_sock);
        close(server_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        X509_free(server_cert);
        return -1;
    }

    size_t decrypted_session_key_len;
    if (EVP_PKEY_decrypt(decrypt_ctx, NULL, &decrypted_session_key_len, (unsigned char *)encrypted_session_key.c_str(), encrypted_session_key.length()) <= 0)
    {
        std::cerr << "EVP_PKEY_decrypt failed to get length" << std::endl;
        EVP_PKEY_CTX_free(decrypt_ctx);
        close(client_sock);
        close(server_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        X509_free(server_cert);
        return -1;
    }

    unsigned char *decrypted_session_key = new unsigned char[decrypted_session_key_len];
    if (EVP_PKEY_decrypt(decrypt_ctx, decrypted_session_key, &decrypted_session_key_len, (unsigned char *)encrypted_session_key.c_str(), encrypted_session_key.length()) <= 0)
    {
        std::cerr << "EVP_PKEY_decrypt failed" << std::endl;
        delete[] decrypted_session_key;
        EVP_PKEY_CTX_free(decrypt_ctx);
        close(client_sock);
        close(server_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        X509_free(server_cert);
        return -1;
    }

    std::string session_key((char *)decrypted_session_key, decrypted_session_key_len);
    delete[] decrypted_session_key;
    EVP_PKEY_CTX_free(decrypt_ctx);

    std::cout << "Session key decrypted successfully" << std::endl;
    std::cout << "Session key: " << stringToHex(session_key) << std::endl;

    std::cout << std::endl;
    std::cout << "=============================" << std::endl;
    std::cout << "SECURE CONNECTION ESTABLISHED" << std::endl;
    std::cout << "    SESSION KEY GENERATED    " << std::endl;
    std::cout << "=============================" << std::endl;
    std::cout << std::endl;

    // Receive messages from the client
    while (true)
    {
        std::string message = receiveMessageFromClient(client_sock);
        if (message.empty())
        {
            close(client_sock);
            close(server_sock);
            EVP_PKEY_free(server_pkey);
            EVP_PKEY_free(temp_pkey);
            X509_free(server_cert);
            return -1;
        }
        std::cout << "Received message from client: " << message << std::endl;

        if (message == "exit")
        {
            break; // Exit the loop
        }
        else if (message == "register" || message == "login")
        {
            // Handle registration or login
            std::string user_info = receiveMessageFromClient(client_sock);
            if (user_info.empty())
            {
                close(client_sock);
                close(server_sock);
                EVP_PKEY_free(server_pkey);
                EVP_PKEY_free(temp_pkey);
                X509_free(server_cert);
                return -1;
            }
            std::cout << "Received user info from client: " << user_info << std::endl;
            // Here you can add logic to handle the received information
        }
        else
        {
            // Handle other messages
        }
    }

    // Close connections and free resources
    close(client_sock);
    close(server_sock);
    EVP_PKEY_free(server_pkey);
    EVP_PKEY_free(temp_pkey);
    X509_free(server_cert);

    return 0;
}
