#include "RSA_utils.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <iostream>

void printRSAKey(RSA *rsa, bool isPrivate)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (isPrivate)
    {
        PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
    }
    else
    {
        PEM_write_bio_RSAPublicKey(bio, rsa);
    }
    char *key_data = NULL;
    long len = BIO_get_mem_data(bio, &key_data);
    std::string key_str(key_data, len);
    std::cout << key_str << std::endl;
    BIO_free(bio);
}

std::string signMessage(RSA *rsa, const std::string &message)
{
    unsigned char hash[32];
    unsigned int sig_len;
    unsigned char *sig = new unsigned char[RSA_size(rsa)];

    if (SHA256((unsigned char *)message.c_str(), message.length(), hash) == NULL)
    {
        std::cerr << "SHA256 calculation failed" << std::endl;
        delete[] sig;
        return "";
    }

    if (RSA_sign(NID_sha256, hash, sizeof(hash), sig, &sig_len, rsa) != 1)
    {
        std::cerr << "Signing failed" << std::endl;
        delete[] sig;
        return "";
    }

    std::string signature((char *)sig, sig_len);
    delete[] sig;
    return signature;
}

bool verifySignature(RSA *rsa, const std::string &message, const std::string &signature)
{
    unsigned char hash[32];
    if (SHA256((unsigned char *)message.c_str(), message.length(), hash) == NULL)
    {
        std::cerr << "SHA256 calculation failed" << std::endl;
        return false;
    }

    if (RSA_verify(NID_sha256, hash, sizeof(hash), (unsigned char *)signature.c_str(), signature.length(), rsa) != 1)
    {
        std::cerr << "Signature verification failed" << std::endl;
        return false;
    }

    return true;
}
