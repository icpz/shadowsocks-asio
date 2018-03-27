
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
                const uint8_t *ad, size_t adlen
        ) {
        int ret;
        unsigned long long clenll;
        ret = crypto_aead_aes256gcm_encrypt(
                    (uint8_t *)c, &clenll,
                    m, mlen, ad, adlen,
                    nullptr, nonce_.data(), key_.data()
              );
        *clen = (size_t)clenll;
        return ret;
    }

    int CipherDecrypt(
                void *m, size_t *mlen,
                const uint8_t *c, size_t clen,
                const uint8_t *ad, size_t adlen
        ) {
        int ret;
        unsigned long long mlenll;
        ret = crypto_aead_aes256gcm_decrypt(
                        (uint8_t *)m, &mlenll,
                        nullptr,
                        c, clen, ad, adlen,
                        nonce_.data(), key_.data()
              );
        *mlen = (size_t)mlenll;
        return ret;
    }
};

using CipherGenerator = const EVP_CIPHER *();
template<CipherGenerator cg, size_t key_len, class Base = AeadCipher<key_len, 12, 16>>
class AesGcmFamily final : public Base {
public:
    AesGcmFamily(std::vector<uint8_t> master_key)
        : Base(std::move(master_key)) {
        ctx_ = EVP_CIPHER_CTX_new();
    }

    ~AesGcmFamily() {
        EVP_CIPHER_CTX_free(ctx_);
    }

private:
    int CipherEncrypt(
                void *c, size_t *clen,
                const uint8_t *m, size_t mlen,
                const uint8_t *ad, size_t adlen
        ) {
        const uint8_t *k = Base::key_.data();
        const uint8_t *n = Base::nonce_.data();
        const size_t tag_len = Base::kTagLength;

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
                  && (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG, tag_len, tag) > 0);
        *clen += cipher_len;
        *clen += tag_len;

        return !ret;
    }

    int CipherDecrypt(
                void *m, size_t *mlen,
                const uint8_t *c, size_t clen,
                const uint8_t *ad, size_t adlen
        ) {
        const uint8_t *k = Base::key_.data();
        const uint8_t *n = Base::nonce_.data();
        const size_t tag_len = Base::kTagLength;

        int ret;
        uint8_t *plaintext = (uint8_t *)m;
        int plain_len = clen - tag_len;
        uint8_t *tag = const_cast<uint8_t *>(c + plain_len);

        EVP_DecryptInit_ex(ctx_, kCipher, nullptr, nullptr, nullptr);
        ret = (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG, tag_len, tag) > 0)
           && (EVP_DecryptInit_ex(ctx_, nullptr, nullptr, k, n) > 0)
           && (adlen == 0 || (EVP_DecryptUpdate(ctx_, nullptr, &plain_len, ad, adlen) > 0))
           && (EVP_DecryptUpdate(ctx_, plaintext, &plain_len, c, clen - tag_len) > 0);
        *mlen = plain_len;
        ret = ret && (EVP_EncryptFinal_ex(ctx_, plaintext + plain_len, &plain_len) > 0);
        *mlen += plain_len;

        return !ret;
    }

    EVP_CIPHER_CTX *ctx_;
    const EVP_CIPHER * kCipher = cg();
};

#define DEFINE_AND_REGISTER(bitlen) \
    using Aes ## bitlen ## Gcm = AesGcmFamily<EVP_aes_ ## bitlen ## _gcm, (bitlen >> 3)>; \
    static const CryptoContextGeneratorRegister<Aes ## bitlen ## Gcm> \
    kReg ## bitlen ("aes-" #bitlen "-gcm");

DEFINE_AND_REGISTER(192);
DEFINE_AND_REGISTER(128);

static const CryptoContextGeneratorRegister<Aes256Gcm> kReg256("aes-256-gcm");

