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

    TlsObfs()
        : hostname_(kArgs->obfs_host) {
        session_id_.back() = 0;
    }

    ~TlsObfs() { }

    ssize_t ObfsRequest(Buffer &buf);
    ssize_t DeObfsResponse(Buffer &buf);

    ssize_t ObfsResponse(Buffer &buf);
    ssize_t DeObfsRequest(Buffer &buf);

    void ResetTarget(TargetInfo &target);
private:
    int obfs_stage_ = 0;
    int deobfs_stage_ = 0;
    std::array<uint8_t, 33> session_id_;
    boost::string_view hostname_;
    Frame extra_ = { 0 };
    TargetInfo forward_target_;
};

#endif

