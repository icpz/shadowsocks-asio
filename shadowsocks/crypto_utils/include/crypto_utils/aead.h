#ifndef __AEAD_H__
#define __AEAD_H__

#include <array>
#include <string>
#include <boost/endian/buffers.hpp>
#include <sodium.h>

#include "crypto_utils/cipher.h"
#include "crypto_utils/crypto.h"

template<size_t key_len, size_t nonce_len, size_t tag_len>
class AeadCipher : public Cipher {
public:
    AeadCipher(std::vector<uint8_t> master_key)
        : Cipher(std::move(master_key)), initialized_(false) {
        std::fill(nonce_.begin(), nonce_.end(), 0);
    }

    virtual ~AeadCipher() = default;

    ssize_t Encrypt(Buffer &buf);
    ssize_t Decrypt(Buffer &buf);

    static void DeriveKeyFromPassword(std::string password, std::vector<uint8_t> &key) {
        key.resize(key_len);
        Cipher::DeriveKeyFromPassword(std::move(password), key);
    }

    virtual bool DeriveSessionKey();

protected:
    virtual int CipherEncrypt(
                    void *c, size_t *clen,
                    const uint8_t *m, size_t mlen,
                    const uint8_t *ad, size_t adlen
                ) = 0;

    virtual int CipherDecrypt(
                    void *m, size_t *mlen,
                    const uint8_t *c, size_t clen,
                    const uint8_t *ad, size_t adlen
                ) = 0;

    const size_t kTagLength = tag_len;
    bool initialized_;
    std::vector<uint8_t> chunk_;
    std::array<uint8_t, key_len> key_;
    std::array<uint8_t, key_len> salt_;
    std::array<uint8_t, nonce_len> nonce_;
};

template<size_t key_len, size_t nonce_len, size_t tag_len>
ssize_t AeadCipher<key_len, nonce_len, tag_len>::Encrypt(Buffer &buf) {
    size_t ciphertext_length = 0;

    chunk_.reserve(buf.Size());
    std::copy(buf.Begin(), buf.End(), std::back_inserter(chunk_));
    buf.Reset();

    if (!initialized_) {
        randombytes_buf(salt_.data(), salt_.size());
        if (!DeriveSessionKey()) {
            LOG(WARNING) << "Key derivation error";
            return -1;
        }
        buf.AppendData(salt_);
        ciphertext_length += salt_.size();
        initialized_ = true;
    }

    size_t processed_length = 0;
    while (processed_length < chunk_.size()) {
        size_t plaintext_length = std::min(chunk_.size() - processed_length, 0x3fffUL);
        boost::endian::big_uint16_buf_t length_buf{ (uint16_t)plaintext_length };
        size_t clen = plaintext_length + sizeof length_buf + tag_len * 2;
        int ret;

        buf.PrepareCapacity(clen);

        ret = CipherEncrypt(
                buf.End(), &clen,
                (uint8_t *)&length_buf, sizeof length_buf,
                nullptr, 0
        );
        if (ret) {
            LOG(WARNING) << "CipherEncrypt error while encrypting length: " << ret;
            return ret;
        }
        sodium_increment(nonce_.data(), nonce_.size());
        buf.Append(clen);
        ciphertext_length += clen;

        ret = CipherEncrypt(
                buf.End(), &clen,
                chunk_.data() + processed_length, plaintext_length,
                nullptr, 0
        );
        if (ret) {
            LOG(WARNING) << "CipherEncrypt error while encrypting data" << ret;
            return ret;
        }
        sodium_increment(nonce_.data(), nonce_.size());
        buf.Append(clen);
        ciphertext_length += clen;
        processed_length += plaintext_length;
    }
    chunk_.erase(chunk_.begin(), chunk_.begin() + processed_length);

    if (ciphertext_length != buf.Size()) {
        LOG(FATAL) << "unexcepted ciphertext length: " << ciphertext_length
                   << ", should be " << buf.Size();
    }

    return ciphertext_length;
}

template<size_t key_len, size_t nonce_len, size_t tag_len>
ssize_t AeadCipher<key_len, nonce_len, tag_len>::Decrypt(Buffer &buf) {
    size_t plaintext_length = 0;

    chunk_.reserve(buf.Size());
    std::copy(buf.Begin(), buf.End(), std::back_inserter(chunk_));
    buf.Reset();

    if (!initialized_) {
        if (chunk_.size() < salt_.size()) { // need more
            return 0;
        }
        std::copy_n(chunk_.begin(), salt_.size(), salt_.begin());
        chunk_.erase(chunk_.begin(), chunk_.begin() + salt_.size());
        if (!DeriveSessionKey()) {
            LOG(WARNING) << "Key derivation error";
            return -1;
        }
        initialized_ = true;
    }

    size_t processed_length = 0;
    while (processed_length < chunk_.size()) {
        boost::endian::big_uint16_buf_t length_buf;
        size_t ciphertext_length = sizeof length_buf + tag_len;
        size_t mlen = sizeof length_buf;
        int ret;

        if (processed_length + ciphertext_length > chunk_.size()) {
            break;
        }

        ret = CipherDecrypt(
                &length_buf, &mlen,
                chunk_.data() + processed_length, ciphertext_length,
                nullptr, 0
        );
        if (ret) {
            LOG(WARNING) << "CipherDecrypt error while decrypting length: " << ret;
            return ret;
        }
        processed_length += mlen + tag_len;
        ciphertext_length = length_buf.value() + tag_len;
        if (processed_length + ciphertext_length > chunk_.size()) {
            processed_length -= mlen + tag_len;
            break;
        }
        sodium_increment(nonce_.data(), nonce_.size());

        buf.PrepareCapacity(length_buf.value());
        ret = CipherDecrypt(
                buf.End(), &mlen,
                chunk_.data() + processed_length, ciphertext_length,
                nullptr, 0
        );
        if (ret) {
            LOG(WARNING) << "CipherDecrypt error while decrypting data: " << ret;
            return ret;
        }
        sodium_increment(nonce_.data(), nonce_.size());
        buf.Append(mlen);
        plaintext_length += mlen;
        processed_length += ciphertext_length;
    }

    if (plaintext_length != buf.Size()) {
        LOG(FATAL) << "unexcepted ciphertext length: " << plaintext_length
                   << ", should be " << buf.Size();
    }

    chunk_.erase(chunk_.begin(), chunk_.begin() + processed_length);

    return plaintext_length;
}

template<size_t key_len, size_t nonce_len, size_t tag_len>
bool AeadCipher<key_len, nonce_len, tag_len>::DeriveSessionKey() {
    return Cipher::HKDF_SHA1(master_key_.data(), master_key_.size(),
                             salt_.data(), salt_.size(),
                             (const uint8_t *)"ss-subkey", 9,
                             key_.data(), key_len);
}

#endif

