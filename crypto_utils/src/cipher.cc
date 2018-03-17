
#include "crypto_utils/cipher.h"

int crypto_derive_key(const char *pass, uint8_t *key, size_t key_len) {
    size_t datal;
    datal = strlen((const char *)pass);

    const mbedtls_md_info_t *md = mbedtls_md_info_from_string("MD5");
    if (md == NULL) {
        LOG(FATAL) << "MD5 Digest not found in crypto library";
    }

    mbedtls_md_context_t c;
    unsigned char md_buf[256];
    int addmd;
    unsigned int i, j, mds;

    mds = mbedtls_md_get_size(md);
    memset(&c, 0, sizeof(mbedtls_md_context_t));

    if (pass == NULL)
        return key_len;
    if (mbedtls_md_setup(&c, md, 1))
        return 0;

    for (j = 0, addmd = 0; j < key_len; addmd++) {
        mbedtls_md_starts(&c);
        if (addmd) {
            mbedtls_md_update(&c, md_buf, mds);
        }
        mbedtls_md_update(&c, (uint8_t *)pass, datal);
        mbedtls_md_finish(&c, &(md_buf[0]));

        for (i = 0; i < mds; i++, j++) {
            if (j >= key_len)
                break;
            key[j] = md_buf[i];
        }
    }

    mbedtls_md_free(&c);
    return key_len;
}

