#ifndef __CIPHER_H__
#define __CIPHER_H__

#include <common_utils/buffer.h>

class Cipher {
public:
    Cipher() = default;
    virtual ~Cipher() = default;

    virtual ssize_t Decrypt(Buffer &buf) = 0; 
    virtual ssize_t Encrypt(Buffer &buf) = 0;

private:
};

#endif

