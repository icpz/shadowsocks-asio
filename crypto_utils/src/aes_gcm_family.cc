
#include <sodium.h>

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
        );

    int CipherDecrypt(
                void *m, size_t *mlen,
                const uint8_t *c, size_t clen,
                const uint8_t *ad, size_t adlen,
                const uint8_t *n, const uint8_t *k
        );
};

int Aes256Gcm::CipherEncrypt(
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

int Aes256Gcm::CipherDecrypt(
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

static const CryptoContextGeneratorRegister<Aes256Gcm> kReg("aes-256-gcm");

