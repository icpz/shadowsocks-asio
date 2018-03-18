
#include <openssl/evp.h>

#include "crypto_utils/crypto.h"
#include "crypto_utils/stream.h"

class Aes256Cfb final : public StreamCipher<32, 16> {
public:
    Aes256Cfb(std::vector<uint8_t> master_key)
        : StreamCipher(std::move(master_key)) {
        ctx_ = EVP_CIPHER_CTX_new();
    }

    ~Aes256Cfb() {
        EVP_CIPHER_CTX_free(ctx_);
    }

private:
    int InitializeCipher(bool enc) {
        return EVP_CipherInit_ex(ctx_, EVP_aes_256_cfb(),
                                 nullptr, master_key_.data(),
                                 iv_.data(), enc);
    }

    int CipherUpdate(void *out, size_t *olen, const uint8_t *in, size_t ilen) {
        int out_len;
        int ret = EVP_CipherUpdate(ctx_, (uint8_t *)out, &out_len, in, ilen);
        *olen = out_len;
        return !ret;
    }

    EVP_CIPHER_CTX *ctx_;
};

CryptoContextGeneratorRegister<Aes256Cfb> kReg256("aes-256-cfb");

