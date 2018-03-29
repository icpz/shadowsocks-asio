
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "crypto_utils/cipher.h"
 
static uint8_t *HKDF(const EVP_MD *evp_md,
                     const uint8_t *salt, size_t salt_len,
                     const uint8_t *key, size_t key_len,
                     const uint8_t *info, size_t info_len,
                     uint8_t *okm, size_t okm_len);

bool Cipher::HKDF_SHA1(const uint8_t *key, size_t key_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *session_key, size_t skey_len) {
    return HKDF(EVP_sha1(), salt, salt_len,
                key, key_len,
                info, info_len,
                session_key, skey_len) != nullptr;
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

    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    uint8_t md_buf[EVP_MAX_MD_SIZE];
    int addmd;
    uint32_t i, j, mds;

    mds = EVP_MD_size(md);

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

    EVP_MD_CTX_destroy(ctx);
    return key_len;
}

static uint8_t *HKDF_Extract(const EVP_MD *evp_md,
                             const uint8_t *salt, size_t salt_len,
                             const uint8_t *key, size_t key_len,
                             uint8_t *prk, size_t *prk_len);

static uint8_t *HKDF_Expand(const EVP_MD *evp_md,
                            const uint8_t *prk, size_t prk_len,
                            const uint8_t *info, size_t info_len,
                            uint8_t *okm, size_t okm_len);

static uint8_t *HKDF(const EVP_MD *evp_md,
                     const uint8_t *salt, size_t salt_len,
                     const uint8_t *key, size_t key_len,
                     const uint8_t *info, size_t info_len,
                     uint8_t *okm, size_t okm_len)
{
    uint8_t prk[EVP_MAX_MD_SIZE];
    uint8_t *ret;
    size_t prk_len;

    if (!HKDF_Extract(evp_md, salt, salt_len, key, key_len, prk, &prk_len))
        return NULL;

    ret = HKDF_Expand(evp_md, prk, prk_len, info, info_len, okm, okm_len);
    OPENSSL_cleanse(prk, sizeof(prk));

    return ret;
}

static uint8_t *HKDF_Extract(const EVP_MD *evp_md,
                             const uint8_t *salt, size_t salt_len,
                             const uint8_t *key, size_t key_len,
                             uint8_t *prk, size_t *prk_len)
{
    uint32_t tmp_len;

    if (!HMAC(evp_md, salt, salt_len, key, key_len, prk, &tmp_len))
        return NULL;

    *prk_len = tmp_len;
    return prk;
}

static uint8_t *HKDF_Expand(const EVP_MD *evp_md,
                            const uint8_t *prk, size_t prk_len,
                            const uint8_t *info, size_t info_len,
                            uint8_t *okm, size_t okm_len)
{
    HMAC_CTX hmac;
    uint32_t i;
    uint8_t prev[EVP_MAX_MD_SIZE];
    size_t done_len = 0, dig_len = EVP_MD_size(evp_md);
    size_t n = okm_len / dig_len;

    if (okm_len % dig_len)
        n++;
    if (n > 255 || okm == NULL)
        return NULL;

    HMAC_CTX_init(&hmac);
    if (!HMAC_Init_ex(&hmac, prk, prk_len, evp_md, NULL))
        goto err;

    for (i = 1; i <= n; i++) {
        size_t copy_len;
        const uint8_t ctr = i;
        if (i > 1) {
            if (!HMAC_Init_ex(&hmac, NULL, 0, NULL, NULL))
                goto err;
            if (!HMAC_Update(&hmac, prev, dig_len))
                goto err;
        }
        if (!HMAC_Update(&hmac, info, info_len))
            goto err;
        if (!HMAC_Update(&hmac, &ctr, 1))
            goto err;
        if (!HMAC_Final(&hmac, prev, NULL))
            goto err;
        copy_len = (done_len + dig_len > okm_len) ?
                       okm_len - done_len :
                       dig_len;
        memcpy(okm + done_len, prev, copy_len);
        done_len += copy_len;
    }
    HMAC_CTX_cleanup(&hmac);
    return okm;

 err:
    HMAC_CTX_cleanup(&hmac);
    return NULL;
}

