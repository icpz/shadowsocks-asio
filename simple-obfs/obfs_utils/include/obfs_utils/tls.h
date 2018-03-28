#ifndef __TLS_H__
#define __TLS_H__

#include <string_view>

#include "obfs_utils/obfs.h"

struct Frame {
    int16_t  idx;
    uint16_t len;
    uint8_t  buf[2];
};

class TlsObfsClient : public Obfuscator {
public:

    TlsObfsClient(std::string_view host, boost::asio::ip::tcp::endpoint ep)
        : Obfuscator(std::move(ep)), hostname_(host) {
    }

    TlsObfsClient(std::string_view obfs_host, std::string host, uint16_t port)
        : Obfuscator(std::move(host), port), hostname_(obfs_host) {
    }

    ~TlsObfsClient() { }

    ssize_t Obfs(Buffer &buf) {
        return ObfsRequest(buf);
    }

    ssize_t DeObfs(Buffer &buf) {
        return DeObfsResponse(buf);
    }

    ssize_t ObfsRequest(Buffer &buf);
    ssize_t DeObfsResponse(Buffer &buf);

private:

    int obfs_stage_ = 0;
    int deobfs_stage_ = 0;
    std::string_view hostname_;
    Frame extra_ = { 0 };
};

#endif

