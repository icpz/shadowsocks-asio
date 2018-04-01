#ifndef __CIPHER_H__
#define __CIPHER_H__

#include <utility>
#include <memory>
#include <type_traits>

#include <common_utils/buffer.h>

class Cipher {
public:
    template<class Container>
        Cipher(Container cont)
            : master_key_(std::begin(cont), std::end(cont)) {
        }
    virtual ~Cipher() = default;

    virtual ssize_t Decrypt(Buffer &buf) = 0; 
    virtual ssize_t Encrypt(Buffer &buf) = 0;

    virtual ssize_t DecryptOnce(Buffer &buf) = 0;
    virtual ssize_t EncryptOnce(Buffer &buf) = 0;

    static void DeriveKeyFromPassword(std::string password, std::vector<uint8_t> &key);

protected:
    static bool HKDF_SHA1(const uint8_t *key, size_t key_len,
                          const uint8_t *salt, size_t salt_len,
                          const uint8_t *info, size_t info_len,
                          uint8_t *session_key, size_t key_length);

    std::vector<uint8_t> master_key_;
};

class CryptoContext {
public:
    virtual ssize_t Decrypt(Buffer &buf) = 0;
    virtual ssize_t Encrypt(Buffer &buf) = 0;

    virtual ssize_t DecryptOnce(Buffer &buf) = 0;
    virtual ssize_t EncryptOnce(Buffer &buf) = 0;
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

    ssize_t DecryptOnce(Buffer &buf) { return decryptor_->DecryptOnce(buf); }
    ssize_t EncryptOnce(Buffer &buf) { return encryptor_->EncryptOnce(buf); }

private:
    std::unique_ptr<Cipher> decryptor_;
    std::unique_ptr<Cipher> encryptor_;
};

template<typename CipherType, typename ...Args>
std::unique_ptr<CryptoContext> GetCryptoContext(Args&& ...args) {
    return std::make_unique<__HelperCryptoContext<CipherType>>(std::forward<Args>(args)...);
}

template<typename CipherType>
decltype(auto) MakeCryptoContextGenerator(std::string password) {
    static_assert(std::is_base_of<Cipher, CipherType>::value, "The cipher type must inherit from Cipher");
    std::vector<uint8_t> master_key;
    CipherType::DeriveKeyFromPassword(std::move(password), master_key);
    return [master_key]() { return GetCryptoContext<CipherType>(master_key); };
}

#endif

