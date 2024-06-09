#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>

// Send a message to the server
bool sendMessageToServer(int client_sock, const std::string &message)
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

// Verify the message signature using the RSA public key
bool verifySignature(EVP_PKEY *pkey, const std::string &message, const std::string &signature)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        std::cerr << "Failed to create EVP_MD_CTX" << std::endl;
        return false;
    }

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1)
    {
        std::cerr << "EVP_DigestVerifyInit failed" << std::endl;
        EVP_MD_CTX_free(ctx);
        return false;
    }

    if (EVP_DigestVerifyUpdate(ctx, message.c_str(), message.length()) != 1)
    {
        std::cerr << "EVP_DigestVerifyUpdate failed" << std::endl;
        EVP_MD_CTX_free(ctx);
        return false;
    }

    if (EVP_DigestVerifyFinal(ctx, (unsigned char *)signature.c_str(), signature.length()) != 1)
    {
        std::cerr << "Signature verification failed" << std::endl;
        EVP_MD_CTX_free(ctx);
        return false;
    }

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

// Receive a message from the server
std::string receiveMessageFromServer(int client_sock)
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

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <server_public_key_file>" << std::endl;
        return -1;
    }

    // Load the server's public key
    const char *pubkey_filename = argv[1];
    FILE *pubkey_file = fopen(pubkey_filename, "r");
    if (!pubkey_file)
    {
        std::cerr << "Unable to open server public key file: " << pubkey_filename << std::endl;
        return -1;
    }

    EVP_PKEY *server_pkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
    fclose(pubkey_file);
    if (!server_pkey)
    {
        std::cerr << "Unable to read server public key" << std::endl;
        return -1;
    }

    std::cout << "Server public key loaded" << std::endl;
    printRSAKey(server_pkey, false);

    // Create the socket
    int client_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sock == -1)
    {
        std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
        EVP_PKEY_free(server_pkey);
        return -1;
    }

    // Configure server address and port
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Connect to the server
    if (connect(client_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        std::cerr << "Connect failed: " << strerror(errno) << std::endl;
        close(client_sock);
        EVP_PKEY_free(server_pkey);
        return -1;
    }

    std::cout << "Connected to server" << std::endl;

    // Generate the random number R
    std::string R = generateRandomNumber();
    std::cout << "Random number R generated: " << stringToHex(R) << std::endl;

    // Send the random number R to the server
    if (!sendMessageToServer(client_sock, R))
    {
        close(client_sock);
        EVP_PKEY_free(server_pkey);
        return -1;
    }

    // Receive the temporary public key from the server
    std::string temp_pub_key_str = receiveMessageFromServer(client_sock);
    if (temp_pub_key_str.empty())
    {
        close(client_sock);
        EVP_PKEY_free(server_pkey);
        return -1;
    }

    BIO *bio = BIO_new_mem_buf((void *)temp_pub_key_str.c_str(), -1);
    EVP_PKEY *temp_pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!temp_pkey)
    {
        std::cerr << "Failed to parse temporary public key" << std::endl;
        close(client_sock);
        EVP_PKEY_free(server_pkey);
        return -1;
    }

    std::cout << "Temporary public key received:" << std::endl;
    printRSAKey(temp_pkey, false);

    // Receive the signature from the server
    std::string signature = receiveMessageFromServer(client_sock);
    if (signature.empty())
    {
        close(client_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        return -1;
    }

    // Receive the server's certificate
    std::string server_cert_str = receiveMessageFromServer(client_sock);
    if (server_cert_str.empty())
    {
        close(client_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        return -1;
    }

    // Load the server's certificate
    BIO *server_cert_bio = BIO_new_mem_buf((void *)server_cert_str.c_str(), -1);
    X509 *server_cert = PEM_read_bio_X509(server_cert_bio, NULL, NULL, NULL);
    BIO_free(server_cert_bio);

    if (!server_cert)
    {
        std::cerr << "Failed to parse server certificate" << std::endl;
        close(client_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        return -1;
    }

    std::cout << "Server certificate received and parsed successfully" << std::endl;

    // Verify the server's certificate (optional)
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, server_cert, NULL);

    if (X509_verify_cert(ctx) != 1)
    {
        std::cerr << "Server certificate verification failed" << std::endl;
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        X509_free(server_cert);
        close(client_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        return -1;
    }

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    // Extract the server's public key from the certificate
    EVP_PKEY *server_cert_pubkey = X509_get_pubkey(server_cert);
    X509_free(server_cert);

    if (!server_cert_pubkey)
    {
        std::cerr << "Failed to extract public key from server certificate" << std::endl;
        close(client_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        return -1;
    }

    // Create the message to verify (R + temporary public key)
    std::string message_to_verify = R + temp_pub_key_str;

    // Verify the signature
    if (!verifySignature(server_cert_pubkey, message_to_verify, signature))
    {
        std::cerr << "Signature verification failed" << std::endl;
        EVP_PKEY_free(server_cert_pubkey);
        close(client_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        return -1;
    }

    EVP_PKEY_free(server_cert_pubkey);

    std::cout << "Signature verified successfully" << std::endl;

    // Generate the session key
    std::string session_key = "this_is_a_secret_key";

    // Encrypt the session key with the temporary public key
    EVP_PKEY_CTX *ctx_enc = EVP_PKEY_CTX_new(temp_pkey, NULL);
    if (!ctx_enc)
    {
        std::cerr << "EVP_PKEY_CTX_new failed" << std::endl;
        close(client_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        return -1;
    }

    if (EVP_PKEY_encrypt_init(ctx_enc) <= 0)
    {
        std::cerr << "EVP_PKEY_encrypt_init failed" << std::endl;
        EVP_PKEY_CTX_free(ctx_enc);
        close(client_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        return -1;
    }

    size_t encrypted_key_len;
    if (EVP_PKEY_encrypt(ctx_enc, NULL, &encrypted_key_len, (unsigned char *)session_key.c_str(), session_key.length()) <= 0)
    {
        std::cerr << "EVP_PKEY_encrypt (get length) failed" << std::endl;
        EVP_PKEY_CTX_free(ctx_enc);
        close(client_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        return -1;
    }

    unsigned char *encrypted_key = (unsigned char *)OPENSSL_malloc(encrypted_key_len);
    if (!encrypted_key)
    {
        std::cerr << "OPENSSL_malloc failed" << std::endl;
        EVP_PKEY_CTX_free(ctx_enc);
        close(client_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        return -1;
    }

    if (EVP_PKEY_encrypt(ctx_enc, encrypted_key, &encrypted_key_len, (unsigned char *)session_key.c_str(), session_key.length()) <= 0)
    {
        std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
        OPENSSL_free(encrypted_key);
        EVP_PKEY_CTX_free(ctx_enc);
        close(client_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx_enc);

    std::string encrypted_key_str((char *)encrypted_key, encrypted_key_len);
    OPENSSL_free(encrypted_key);

    std::cout << "Symmetric key encrypted: " << stringToHex(encrypted_key_str) << std::endl;

    // Send the encrypted symmetric key to the server
    if (!sendMessageToServer(client_sock, encrypted_key_str))
    {
        close(client_sock);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(temp_pkey);
        return -1;
    }

    // Close the connection and free resources
    close(client_sock);
    EVP_PKEY_free(server_pkey);
    EVP_PKEY_free(temp_pkey);

    return 0;
}
