#ifndef __TLS_H__
#define __TLS_H__

#include <boost/utility/string_view.hpp>

#include "obfs_utils/obfs.h"

struct Frame {
    int16_t  idx;
    uint16_t len;
    uint8_t  buf[2];
};

class TlsObfs : public Obfuscator {
public:

    TlsObfs(boost::string_view obfs_host)
        : hostname_(obfs_host) {
    }

    ~TlsObfs() { }

    ssize_t ObfsRequest(Buffer &buf);
    ssize_t DeObfsResponse(Buffer &buf);

    ssize_t ObfsResponse(Buffer &buf);
    ssize_t DeObfsRequest(Buffer &buf);

private:
    int obfs_stage_ = 0;
    int deobfs_stage_ = 0;
    boost::string_view hostname_;
    Frame extra_ = { 0 };
};

#endif

