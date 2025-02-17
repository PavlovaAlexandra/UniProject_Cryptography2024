#include "encryptionAES.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <vector>
#include <cstring>

bool aes_encrypt(const std::string &plain_text, std::string &encrypted_text, const std::string &key, std::string &iv)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return false;
    }

    int len;
    int ciphertext_len;

    std::vector<unsigned char> ciphertext(plain_text.size() + EVP_MAX_BLOCK_LENGTH);

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)key.c_str(), (const unsigned char*)iv.c_str()))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (const unsigned char*)plain_text.c_str(), plain_text.size()))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    encrypted_text.assign((char*)ciphertext.data(), ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aes_decrypt(const std::string &encrypted_text, std::string &plain_text, const std::string &key, const std::string &iv)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return false;
    }

    int len;
    int plaintext_len;

    std::vector<unsigned char> plaintext(encrypted_text.size());

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)key.c_str(), (const unsigned char*)iv.c_str()))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, (const unsigned char*)encrypted_text.c_str(), encrypted_text.size()))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;

    plain_text.assign((char*)plaintext.data(), plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}
