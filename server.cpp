#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/bn.h>

// Генерация RSA ключей
RSA *generateRSAKey()
{
    int bits = 2048;
    unsigned long e = RSA_F4;
    RSA *rsa = RSA_new();
    BIGNUM *bne = BN_new();

    if (!BN_set_word(bne, e) || !RSA_generate_key_ex(rsa, bits, bne, NULL))
    {
        RSA_free(rsa);
        BN_free(bne);
        return nullptr;
    }

    BN_free(bne);
    return rsa;
}

// Генерация DH параметров
DH* generateDHParamsWithCustomPQ() {
    const char* p_str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
    const char* q_str = "2";

    BIGNUM* p_bn = BN_new();
    BIGNUM* q_bn = BN_new();

    if (!p_bn || !q_bn || !BN_hex2bn(&p_bn, p_str) || !BN_hex2bn(&q_bn, q_str)) {
        std::cerr << "Failed to convert p or q to BIGNUM" << std::endl;
        BN_free(p_bn);
        BN_free(q_bn);
        return nullptr;
    }

    DH* dh = DH_new();
    if (!dh || !DH_set0_pqg(dh, p_bn, NULL, q_bn)) {
        std::cerr << "Failed to set custom p and q for DH" << std::endl;
        BN_free(p_bn);
        BN_free(q_bn);
        DH_free(dh);
        return nullptr;
    }

    return dh;
}



// Генерация секретного ключа на основе общих параметров DH и открытого ключа клиента
unsigned char *generateSharedSecret(DH *dh, const char *client_public_key)
{
    BIGNUM *client_pub = BN_new();
    BN_hex2bn(&client_pub, client_public_key);

    unsigned char *secret = new unsigned char[DH_size(dh)];
    DH_compute_key(secret, client_pub, dh);

    BN_free(client_pub);
    return secret;
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
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(12345);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    // Привязка сокета к адресу
    if (bind(server_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        std::cerr << "Bind failed: " << strerror(errno) << std::endl;
        close(server_sock);
        return -1;
    }

    // Прослушивание входящих соединений
    if (listen(server_sock, 1) == -1)
    {
        std::cerr << "Listen failed: " << strerror(errno) << std::endl;
        close(server_sock);
        return -1;
    }

    std::cout << "Server is listening on port 12345..." << std::endl;

    // Принятие входящего соединения
    int client_sock = accept(server_sock, NULL, NULL);
    if (client_sock == -1)
    {
        std::cerr << "Accept failed: " << strerror(errno) << std::endl;
        close(server_sock);
        return -1;
    }

    std::cout << "Client connected" << std::endl;

    // Генерация RSA ключей
    RSA *rsa = generateRSAKey();
    if (!rsa)
    {
        std::cerr << "RSA key generation failed" << std::endl;
        close(client_sock);
        close(server_sock);
        return -1;
    }

    // Экспорт открытого ключа RSA
    BIO *bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_RSAPublicKey(bio, rsa))
    {
        std::cerr << "RSA public key export failed" << std::endl;
        close(client_sock);
        close(server_sock);
        RSA_free(rsa);
        return -1;
    }

    char *pub_key;
    long pub_key_len = BIO_get_mem_data(bio, &pub_key);

    std::cout << "RSA key pair generated" << std::endl;
    std::cout << "RSA public key exported" << std::endl;
    std::cout << "Exported RSA key: " << std::string(pub_key, pub_key_len) << std::endl;

    // Отправка открытого ключа RSA клиенту
    if (send(client_sock, pub_key, pub_key_len, 0) == -1)
    {
        std::cerr << "Send failed: " << strerror(errno) << std::endl;
        close(client_sock);
        close(server_sock);
        RSA_free(rsa);
        return -1;
    }

    std::cout << "RSA public key sent to client" << std::endl;
    BIO_free_all(bio);

    // Получение открытого ключа Диффи-Хеллмана от клиента
    char client_pub_key[2048];
    int len = read(client_sock, client_pub_key, sizeof(client_pub_key) - 1);
    if (len == -1)
    {
        std::cerr << "Read failed: " << strerror(errno) << std::endl;
        close(client_sock);
        close(server_sock);
        RSA_free(rsa);
        return -1;
    }
    client_pub_key[len] = '\0';

    std::cout << "DH public key received from client" << std::endl;
    std::cout << "Received DH key: " << client_pub_key << std::endl;

    // Генерация параметров Диффи-Хеллмана
    DH *dh = generateDHParamsWithCustomPQ();
    if (!dh)
    {
        std::cerr << "DH parameters generation failed" << std::endl;
        close(client_sock);
        close(server_sock);
        RSA_free(rsa);
        return -1;
    }

    // Генерация ключей Диффи-Хеллмана
    if (!DH_generate_key(dh))
    {
        std::cerr << "DH key generation failed" << std::endl;
        DH_free(dh);
        close(client_sock);
        close(server_sock);
        RSA_free(rsa);
        return -1;
    }

    const BIGNUM *dh_pub_key = nullptr;
    DH_get0_key(dh, &dh_pub_key, nullptr);
    char *dh_pub_key_str = BN_bn2hex(dh_pub_key);

    // Отправка открытого ключа Диффи-Хеллмана клиенту
    send(client_sock, dh_pub_key_str, strlen(dh_pub_key_str), 0);
    OPENSSL_free(dh_pub_key_str);

    std::cout << "DH public key sent to client" << std::endl;

    // Получение секретного ключа
    unsigned char *shared_secret = generateSharedSecret(dh, client_pub_key);
    if (!shared_secret)
    {
        std::cerr << "DH shared secret generation failed" << std::endl;
        DH_free(dh);
        close(client_sock);
        close(server_sock);
        RSA_free(rsa);
        return -1;
    }

    std::cout << "Shared secret generated: ";
    for (int i = 0; i < DH_size(dh); ++i)
    {
        std::cout << std::hex << static_cast<int>(shared_secret[i]);
    }
    std::cout << std::endl;

    // Отправка сообщения клиенту (по зашифрованному каналу)
    const char *message = "This is a secret message";
    if (send(client_sock, message, strlen(message), 0) == -1)
    {
        std::cerr << "Send failed: " << strerror(errno) << std::endl;
        delete[] shared_secret;
        DH_free(dh);
        close(client_sock);
        close(server_sock);
        RSA_free(rsa);
        return -1;
    }

    std::cout << "Message sent to client" << std::endl;

    delete[] shared_secret;
    DH_free(dh);
    close(client_sock);
    close(server_sock);
    RSA_free(rsa);

    return 0;
}
