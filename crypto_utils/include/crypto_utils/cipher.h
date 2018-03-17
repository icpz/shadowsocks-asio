#ifndef __CIPHER_H__
#define __CIPHER_H__

#include <utility>
#include <memory>
#include <type_traits>
#include <mbedtls/md.h>

#include <common_utils/buffer.h>

class Cipher {
public:
    Cipher() = default;
    virtual ~Cipher() = default;

    virtual ssize_t Decrypt(Buffer &buf) = 0; 
    virtual ssize_t Encrypt(Buffer &buf) = 0;

private:
};

class CryptoContext {
public:
    virtual ssize_t Decrypt(Buffer &buf) = 0;
    virtual ssize_t Encrypt(Buffer &buf) = 0;
};

template<typename CipherType>
class __HelperCryptoContext : public CryptoContext {
    static_assert(std::is_base_of<Cipher, CipherType>::value, "The cipher type must inherit from Cipher");
public:
    template<typename ...Args>
        __HelperCryptoContext(Args&& ...args)
            : decryptor_(new CipherType(std::forward<Args>(args)...)),
              encryptor_(new CipherType(std::forward<Args>(args)...)) {
        }

    ssize_t Decrypt(Buffer &buf) { return decryptor_->Decrypt(buf); }
    ssize_t Encrypt(Buffer &buf) { return encryptor_->Encrypt(buf); }

private:
    std::unique_ptr<Cipher> decryptor_;
    std::unique_ptr<Cipher> encryptor_;
};

template<typename CipherType, typename ...Args>
std::unique_ptr<CryptoContext> GetCryptoContext(Args&& ...args) {
    return std::make_unique<__HelperCryptoContext<CipherType>>(std::forward<Args>(args)...);
}

int crypto_derive_key(const char *pass, uint8_t *key, size_t key_len);

#endif

