
#include <sodium.h>
#include <openssl/evp.h>

#include "crypto_utils/crypto.h"
#include "crypto_utils/aead.h"

class Aes256Gcm final : public AeadCipher<32, 12, 16> {
public:
    Aes256Gcm(std::vector<uint8_t> master_key)
        : AeadCipher(std::move(master_key)) {
    }

    ~Aes256Gcm() { }

private:
    int CipherEncrypt(
                void *c, size_t *clen,
                const uint8_t *m, size_t mlen,
                const uint8_t *ad, size_t adlen,
                const uint8_t *n, const uint8_t *k
        ) {
        int ret;
        unsigned long long clenll;
        ret = crypto_aead_aes256gcm_encrypt(
                    (uint8_t *)c, &clenll,
                    m, mlen, ad, adlen,
                    nullptr, n, k
              );
        *clen = (size_t)clenll;
        return ret;
    }

    int CipherDecrypt(
                void *m, size_t *mlen,
                const uint8_t *c, size_t clen,
                const uint8_t *ad, size_t adlen,
                const uint8_t *n, const uint8_t *k
        ) {
        int ret;
        unsigned long long mlenll;
        ret = crypto_aead_aes256gcm_decrypt(
                        (uint8_t *)m, &mlenll,
                        nullptr,
                        c, clen, ad, adlen,
                        n, k
              );
        *mlen = (size_t)mlenll;
        return ret;
    }
};

class Aes192Gcm final : public AeadCipher<24, 12, 16> {
public:
    Aes192Gcm(std::vector<uint8_t> master_key)
        : AeadCipher(std::move(master_key)) {
        ctx_ = EVP_CIPHER_CTX_new();
    }

    ~Aes192Gcm() {
        EVP_CIPHER_CTX_free(ctx_);
    }

private:
    int CipherEncrypt(
                void *c, size_t *clen,
                const uint8_t *m, size_t mlen,
                const uint8_t *ad, size_t adlen,
                const uint8_t *n, const uint8_t *k
        ) {
        int ret;
        uint8_t *ciphertext = (uint8_t *)c;
        int cipher_len = mlen;
        uint8_t *tag = ciphertext + mlen;

        EVP_EncryptInit_ex(ctx_, kCipher, nullptr, nullptr, nullptr);
        ret = (EVP_EncryptInit_ex(ctx_, nullptr, nullptr, k, n) > 0)
           && (adlen == 0 || (EVP_EncryptUpdate(ctx_, nullptr, &cipher_len, ad, adlen) > 0))
           && (EVP_EncryptUpdate(ctx_, ciphertext, &cipher_len, m, mlen) > 0);
        *clen = cipher_len;
        ret = ret && (EVP_EncryptFinal_ex(ctx_, ciphertext + cipher_len, &cipher_len) > 0)
                  && (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG, kTagLength, tag) > 0);
        *clen += cipher_len;
        *clen += kTagLength;

        return !ret;
    }

    int CipherDecrypt(
                void *m, size_t *mlen,
                const uint8_t *c, size_t clen,
                const uint8_t *ad, size_t adlen,
                const uint8_t *n, const uint8_t *k
        ) {
        int ret;
        uint8_t *plaintext = (uint8_t *)m;
        int plain_len = clen - kTagLength;
        uint8_t *tag = const_cast<uint8_t *>(c + plain_len);

        EVP_DecryptInit_ex(ctx_, kCipher, nullptr, nullptr, nullptr);
        ret = (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG, kTagLength, tag) > 0)
           && (EVP_DecryptInit_ex(ctx_, nullptr, nullptr, k, n) > 0)
           && (adlen == 0 || (EVP_DecryptUpdate(ctx_, nullptr, &plain_len, ad, adlen) > 0))
           && (EVP_DecryptUpdate(ctx_, plaintext, &plain_len, c, clen - kTagLength) > 0);
        *mlen = plain_len;
        ret = ret && (EVP_EncryptFinal_ex(ctx_, plaintext + plain_len, &plain_len) > 0);
        *mlen += plain_len;

        return !ret;
    }

    EVP_CIPHER_CTX *ctx_;
    const EVP_CIPHER * const kCipher = EVP_aes_192_gcm();
};

class Aes128Gcm final : public AeadCipher<16, 12, 16> {
public:
    Aes128Gcm(std::vector<uint8_t> master_key)
        : AeadCipher(std::move(master_key)) {
        ctx_ = EVP_CIPHER_CTX_new();
    }

    ~Aes128Gcm() {
        EVP_CIPHER_CTX_free(ctx_);
    }

private:
    int CipherEncrypt(
                void *c, size_t *clen,
                const uint8_t *m, size_t mlen,
                const uint8_t *ad, size_t adlen,
                const uint8_t *n, const uint8_t *k
        ) {
        int ret;
        uint8_t *ciphertext = (uint8_t *)c;
        int cipher_len = mlen;
        uint8_t *tag = ciphertext + mlen;

        EVP_EncryptInit_ex(ctx_, kCipher, nullptr, nullptr, nullptr);
        ret = (EVP_EncryptInit_ex(ctx_, nullptr, nullptr, k, n) > 0)
           && (adlen == 0 || (EVP_EncryptUpdate(ctx_, nullptr, &cipher_len, ad, adlen) > 0))
           && (EVP_EncryptUpdate(ctx_, ciphertext, &cipher_len, m, mlen) > 0);
        *clen = cipher_len;
        ret = ret && (EVP_EncryptFinal_ex(ctx_, ciphertext + cipher_len, &cipher_len) > 0)
                  && (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG, kTagLength, tag) > 0);
        *clen += cipher_len;
        *clen += kTagLength;

        return !ret;
    }

    int CipherDecrypt(
                void *m, size_t *mlen,
                const uint8_t *c, size_t clen,
                const uint8_t *ad, size_t adlen,
                const uint8_t *n, const uint8_t *k
        ) {
        int ret;
        uint8_t *plaintext = (uint8_t *)m;
        int plain_len = clen - kTagLength;
        uint8_t *tag = const_cast<uint8_t *>(c + plain_len);

        EVP_DecryptInit_ex(ctx_, kCipher, nullptr, nullptr, nullptr);
        ret = (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG, kTagLength, tag) > 0)
           && (EVP_DecryptInit_ex(ctx_, nullptr, nullptr, k, n) > 0)
           && (adlen == 0 || (EVP_DecryptUpdate(ctx_, nullptr, &plain_len, ad, adlen) > 0))
           && (EVP_DecryptUpdate(ctx_, plaintext, &plain_len, c, clen - kTagLength) > 0);
        *mlen = plain_len;
        ret = ret && (EVP_EncryptFinal_ex(ctx_, plaintext + plain_len, &plain_len) > 0);
        *mlen += plain_len;

        return !ret;
    }

    EVP_CIPHER_CTX *ctx_;
    const EVP_CIPHER * const kCipher = EVP_aes_128_gcm();
};

static const CryptoContextGeneratorRegister<Aes256Gcm> kReg256("aes-256-gcm");
static const CryptoContextGeneratorRegister<Aes192Gcm> kReg192("aes-192-gcm");
static const CryptoContextGeneratorRegister<Aes128Gcm> kReg128("aes-128-gcm");

