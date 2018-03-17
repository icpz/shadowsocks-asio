
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "crypto_utils/cipher.h"

bool Cipher::HKDF_SHA1(const uint8_t *key, size_t key_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *session_key, size_t skey_len) {
    bool result = true;
    EVP_PKEY_CTX *ctx;
    size_t outlen = skey_len;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    result = (EVP_PKEY_derive_init(ctx) > 0)
          && (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha1()) > 0)
          && (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, salt_len) > 0)
          && (EVP_PKEY_CTX_set1_hkdf_key(ctx, key, key_len) > 0)
          && (EVP_PKEY_CTX_add1_hkdf_info(ctx, info, info_len) > 0)
          && (EVP_PKEY_derive(ctx, session_key, &outlen) > 0);
    result = result && (outlen == skey_len);

    return result;
}

static size_t __BytesToKey(const std::string &password, uint8_t *key, size_t key_len);

void Cipher::DeriveKeyFromPassword(std::string password, std::vector<uint8_t> &key) {
    size_t key_len = key.size();
    __BytesToKey(password, key.data(), key_len);
}

size_t __BytesToKey(const std::string &password, uint8_t *key, size_t key_len) {
    size_t datal = password.size();
    const uint8_t *pass = (const uint8_t *)password.data();

    const EVP_MD *md = EVP_md5();
    if (md == NULL) {
        LOG(FATAL) << "MD5 Digest not found in crypto library";
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    uint8_t md_buf[EVP_MAX_MD_SIZE];
    int addmd;
    unsigned int i, j, mds;

    mds = EVP_MD_CTX_size(ctx);

    for (j = 0, addmd = 0; j < key_len; addmd++) {
        EVP_DigestInit_ex(ctx, md, NULL);
        if (addmd) {
            EVP_DigestUpdate(ctx, md_buf, mds);
        }
        EVP_DigestUpdate(ctx, pass, datal);
        EVP_DigestFinal_ex(ctx, &(md_buf[0]), &mds);

        for (i = 0; i < mds; i++, j++) {
            if (j >= key_len)
                break;
            key[j] = md_buf[i];
        }
    }

    EVP_MD_CTX_free(ctx);
    return key_len;
}

