#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

// Генерация случайного сессионного ключа
void generateSessionKey(unsigned char *key, size_t len)
{
    RAND_bytes(key, len);
}

// Генерация секретного ключа на основе общих параметров DH и открытого ключа сервера
unsigned char *generateSharedSecret(DH *dh, const char *server_pub_key)
{
    BIGNUM *server_pub = BN_new();
    BN_hex2bn(&server_pub, server_pub_key);

    unsigned char *secret = new unsigned char[DH_size(dh)];
    DH_compute_key(secret, server_pub, dh);

    BN_free(server_pub);
    return secret;
}

int main()
{
    // Создание сокета
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
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
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        std::cerr << "Connection failed: " << strerror(errno) << std::endl;
        close(sock);
        return -1;
    }

    std::cout << "Connected to server" << std::endl;

    // Получение открытого ключа RSA от сервера
    char pub_key[2048];
    int len = read(sock, pub_key, sizeof(pub_key) - 1);
    if (len == -1)
    {
        std::cerr << "Read failed: " << strerror(errno) << std::endl;
        close(sock);
        return -1;
    }
    pub_key[len] = '\0';

    std::cout << "RSA public key received from server" << std::endl;
    std::cout << "Received RSA key: " << pub_key << std::endl;

    // Инициализация RSA структуры с открытым ключом
    BIO *pub = BIO_new_mem_buf(pub_key, len);
    RSA *rsa = PEM_read_bio_RSAPublicKey(pub, NULL, NULL, NULL);
    if (!rsa)
    {
        std::cerr << "RSA public key initialization failed" << std::endl;
        std::cerr << "Error: " << ERR_reason_error_string(ERR_get_error()) << std::endl;
        close(sock);
        return -1;
    }

    std::cout << "RSA public key initialized" << std::endl;

    BIO_free_all(pub);

    // Генерация параметров Диффи-Хеллмана
    DH *dh = DH_new();
    if (!dh)
    {
        std::cerr << "DH parameters initialization failed" << std::endl;
        close(sock);
        RSA_free(rsa);
        return -1;
    }

    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();
    BN_hex2bn(&p, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF");
    BN_hex2bn(&g, "2");
    DH_set0_pqg(dh, p, NULL, g);

    // Генерация ключей Диффи-Хеллмана
    if (!DH_generate_key(dh))
    {
        std::cerr << "DH key generation failed" << std::endl;
        DH_free(dh);
        close(sock);
        RSA_free(rsa);
        return -1;
    }

    const BIGNUM *dh_pub_key = nullptr;
    DH_get0_key(dh, &dh_pub_key, nullptr);
    char *dh_pub_key_str = BN_bn2hex(dh_pub_key);

    // Отправка открытого ключа Диффи-Хеллмана серверу
    send(sock, dh_pub_key_str, strlen(dh_pub_key_str), 0);
    OPENSSL_free(dh_pub_key_str);

    std::cout << "DH public key sent to server" << std::endl;

    // Получение открытого ключа Диффи-Хеллмана от сервера
    char server_pub_key[2048];
    len = read(sock, server_pub_key, sizeof(server_pub_key) - 1);
    if (len == -1)
    {
        std::cerr << "Read failed: " << strerror(errno) << std::endl;
        close(sock);
        RSA_free(rsa);
        DH_free(dh);
        return -1;
    }
    server_pub_key[len] = '\0';

    std::cout << "DH public key received from server" << std::endl;
    std::cout << "Received DH key: " << server_pub_key << std::endl;

    // Получение секретного ключа
    unsigned char *shared_secret = generateSharedSecret(dh, server_pub_key);
    if (!shared_secret)
    {
        std::cerr << "DH shared secret generation failed" << std::endl;
        close(sock);
        RSA_free(rsa);
        DH_free(dh);
        return -1;
    }

    std::cout << "Shared secret generated: ";
    for (int i = 0; i < DH_size(dh); ++i)
    {
        std::cout << std::hex << static_cast<int>(shared_secret[i]);
    }
    std::cout << std::endl;

    // Обмен данными по секретному ключу (здесь просто получение сообщения от сервера)
    char buffer[1024];
    len = read(sock, buffer, sizeof(buffer) - 1);
    if (len == -1)
    {
        std::cerr << "Read failed: " << strerror(errno) << std::endl;
        close(sock);
        RSA_free(rsa);
        DH_free(dh);
        return -1;
    }
    buffer[len] = '\0';

    std::cout << "Server message received: " << buffer << std::endl;

    close(sock);
    RSA_free(rsa);
    DH_free(dh);
    delete[] shared_secret;

    return 0;
}
