
#include <openssl/evp.h>

#include "crypto_utils/crypto.h"
#include "crypto_utils/stream.h"

using CipherGenerator = const EVP_CIPHER *();
template<CipherGenerator cg, size_t key_len, class Base = StreamCipher<key_len, 16>>
class AesCfbFamily final : public Base {
public:
    AesCfbFamily(std::vector<uint8_t> master_key)
        : Base(std::move(master_key)) {
        ctx_ = EVP_CIPHER_CTX_new();
    }

    ~AesCfbFamily() {
        EVP_CIPHER_CTX_free(ctx_);
    }

private:
    int InitializeCipher(bool enc) {
        return EVP_CipherInit_ex(ctx_, cg(), nullptr,
                                 Base::master_key_.data(),
                                 Base::iv_.data(), enc);
    }

    int CipherUpdate(void *out, size_t *olen, const uint8_t *in, size_t ilen) {
        int out_len;
        int ret = EVP_CipherUpdate(ctx_, (uint8_t *)out, &out_len, in, ilen);
        *olen = out_len;
        return !ret;
    }

    EVP_CIPHER_CTX *ctx_;
};

#define DEFINE_AND_REGISTER(bitlen) \
    using Aes ## bitlen ## Cfb = AesCfbFamily<EVP_aes_ ## bitlen ## _cfb, (bitlen >> 3)>; \
    static const CryptoContextGeneratorRegister<Aes ## bitlen ## Cfb> \
    kReg ## bitlen ("aes-" #bitlen "-cfb");

DEFINE_AND_REGISTER(256);
DEFINE_AND_REGISTER(192);
DEFINE_AND_REGISTER(128);

