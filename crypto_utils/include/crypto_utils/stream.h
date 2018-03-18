#ifndef __STREAM_H__
#define __STREAM_H__

#include <sodium.h>
#include <common_utils/buffer.h>

#include "crypto_utils/cipher.h"

template<size_t key_len, size_t iv_len>
class StreamCipher : public Cipher {
public:
    StreamCipher(std::vector<uint8_t> master_key)
        : Cipher(std::move(master_key)), initialized_(false) {
    }

    virtual ~StreamCipher() = default;

    ssize_t Encrypt(Buffer &buf);
    ssize_t Decrypt(Buffer &buf);

    static void DeriveKeyFromPassword(std::string password, std::vector<uint8_t> &key) {
        key.resize(key_len);
        Cipher::DeriveKeyFromPassword(std::move(password), key);
    }

protected:
    virtual int InitializeCipher(bool enc) = 0;

    virtual int CipherUpdate(void *out, size_t *olen, const uint8_t *in, size_t ilen) = 0;

    const size_t kKeyLength = key_len;
    bool initialized_;
    std::vector<uint8_t> chunk_;
    std::array<uint8_t, iv_len> iv_;
};

template<size_t key_len, size_t iv_len>
ssize_t StreamCipher<key_len, iv_len>::Encrypt(Buffer &buf) {
    chunk_.reserve(buf.Size());
    std::copy(buf.Begin(), buf.End(), std::back_inserter(chunk_));
    buf.Reset();

    if (!initialized_) {
        randombytes_buf(iv_.data(), iv_.size());
        buf.AppendData(iv_);
        if (InitializeCipher(true) < 0) {
            LOG(WARNING) << "Stream cipher initialize error";
            return -1;
        }
        initialized_ = true;
    }

    size_t plaintext_length = chunk_.size();
    buf.PrepareCapacity(plaintext_length);
    size_t clen;
    int ret = CipherUpdate(buf.End(), &clen, chunk_.data(), plaintext_length);
    if (ret) {
        LOG(WARNING) << "Stream cipher encrypt failed: " << ret;
        return ret;
    }
    buf.Append(clen);
    chunk_.clear();
    return clen;
}

template<size_t key_len, size_t iv_len>
ssize_t StreamCipher<key_len, iv_len>::Decrypt(Buffer &buf) {
    chunk_.reserve(buf.Size());
    std::copy(buf.Begin(), buf.End(), std::back_inserter(chunk_));
    buf.Reset();

    if (!initialized_) {
        if (chunk_.size() < iv_.size()) {
            return 0;
        }
        std::copy_n(chunk_.begin(), iv_.size(), iv_.begin());
        chunk_.erase(chunk_.begin(), chunk_.begin() + iv_.size());
        if (InitializeCipher(false) < 0) {
            LOG(WARNING) << "Stream cipher initialize error";
            return -1;
        }
        initialized_ = true;
    }

    size_t ciphertext_length = chunk_.size();
    buf.PrepareCapacity(ciphertext_length);
    size_t mlen;
    int ret = CipherUpdate(buf.End(), &mlen, chunk_.data(), ciphertext_length);
    if (ret) {
        LOG(WARNING) << "Stream cipher decrypt failed: " << ret;
        return ret;
    }
    buf.Append(mlen);
    chunk_.clear();
    return mlen;
}

#endif

